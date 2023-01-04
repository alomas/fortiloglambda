import json
import configparser
import os
import time

import boto3
import email

from botocore.exceptions import ClientError


def getconfig():
    config = configparser.ConfigParser()
    config.read('fwloglambda.cfg')
    try:
        logtable = config['loginfo']['logtable']
        actiontable = config['loginfo']['actiontable']
        awsregion = config['loginfo']['awsregion']
        badiptable = config['loginfo']['badiptable']
    except KeyError as e:
        print("No config file, so pulling info from my user's AWS tags.")
        iam = boto3.resource("iam")
        user = iam.CurrentUser()
        tagset = user.tags
        for tag in tagset:
            if tag['Key'] == 'AWSRegion':
                awsregion = tag['Value']
            if tag['Key'] == 'LogTable':
                logtable = tag['Value']
            if tag['Key'] == 'ActionTable':
                actiontable = tag['Value']
            if tag['Key'] == 'BadIPTable':
                badiptable = tag['Value']

    configobj = {}
    configobj["logtable"] = logtable
    configobj["awsregion"] = awsregion
    configobj["actiontable"] = actiontable
    configobj["badiptable"] = badiptable
    return configobj

def getlogdict(msg, logtable, actiontable, badiptable, awsregion):
    if msg.is_multipart():
        payload = msg.get_payload()
    contenttype = msg.get_content_disposition()
    mime = msg.get_payload()
    # This is a placeholder until we figure out how to process non base64 encoded mails
    if contenttype == None:
        payload = str(msg.get_payload(decode=True), 'UTF-8')
        lines = payload.splitlines()
        for line in lines:
            quoteopen = False
            newstring = ""
            if len(line) > 5 and line[0:5] == "date=":
                for pos in range(0, len(line)):
                    therow = line
                    f = therow[pos]
                    if f == '"':
                        quoteopen = not quoteopen
                    if f == " " and not quoteopen:
                        newstring += "|"
                    else:
                        newstring += f
                fields = newstring.split('|')
                logdict = {}
                for field in fields:
                    if "=" in field:
                        values = field.split('=')
                        logdict[values[0]] = values[1].replace('"', '')
                dynamodb = boto3.resource("dynamodb", region_name=awsregion)
                table = dynamodb.Table(logtable)
                logdict["FortiLogID"] = logdict["devname"] + "-" + logdict["logid"] + logdict["eventtime"]
                actiondict = {}
                fortilogid = logdict["devname"] + "_" + logdict["action"] + "_"
                if "status" in logdict:
                    fortilogid += logdict["status"]
                actiondict["FortiLogID"] = fortilogid
                actiondict["action"] = logdict["action"]

                if "status" in logdict:
                    actiondict["status"] = logdict["status"]
                try:
                    response = table.get_item(Key={'FortiLogID': fortilogid}, TableName="FortiLogsActions")
                except ClientError as e:
                    print(e.response['Error']['Message'])
                    print("No Item exists, yet")
                else:
                    if "Item" in response:
                        item = response['Item']
                        if "count" in item:
                            actiondict["count"] = item["count"] + 1
                        else:
                            actiondict["count"] = 1
                    else:
                        actiondict["count"] = 1
                badipdict = {}

                if "srcip" in logdict or "remip" in logdict:
                    if "srcip" in logdict:
                        fortilogid = logdict["devname"] + "_" + logdict["srcip"]
                        badipdict["srcip"] = logdict["srcip"]
                    else:
                        fortilogid = logdict["devname"] + "_" + logdict["remip"]
                        badipdict["srcip"] = logdict["remip"]
                    badipdict["FortiLogID"] = fortilogid
                    try:
                        response = table.get_item(Key={'FortiLogID': fortilogid}, TableName=badiptable)
                    except ClientError as e:
                        print(e.response['Error']['Message'])
                        print("No Item exists, yet")
                    else:
                        if "Item" in response:
                            item = response["Item"]
                            badipdict["count"] = item["count"] + 1
                            print(item)
                        else:
                            badipdict["count"] = 1
                t_epoch = time.time()
                expiretime = int(t_epoch) + 630077

                logdict["exptime"]=expiretime
                table.put_item(TableName=logtable, Item=logdict)
                table.put_item(TableName=actiontable, Item=actiondict)
                if not badipdict=={}:
                    if "status" in logdict:
                        if logdict["status"] == "failure" or logdict["status"] == "failed" or logdict["action"] == "ssl-login-fail":
                            table.put_item(TableName=badiptable, Item=badipdict)

                print(logdict)
                return logdict

def main(key):
    configobj = getconfig()
    s3res = boto3.resource('s3')
    bucketname = os.getenv("bucketname")
    bucket = s3res.Bucket(bucketname)
    prefix = "incoming/"
    s3 = boto3.client('s3')
    print(key)
    objectdata = s3.get_object(Bucket=bucketname, Key=key)
    streaming_object = objectdata["Body"]
    data = streaming_object.read().decode('utf-8')
    msg = email.message_from_string(data)
    logdict = getlogdict(msg,configobj["logtable"], configobj["actiontable"], configobj["badiptable"], configobj["awsregion"])
    s3.put_object(Body=data, Bucket=bucketname, Key=f'{key.replace("incoming", "processed")}')
    s3.delete_object(Bucket=bucketname, Key=key)

def lambda_handler(event, context):
    print(json.dumps(event))
    if "Records" in event:
        records = event["Records"]
        for record in records:
            if record['eventName'] == 'ObjectCreated:Put':
                key = record['s3']['object']['key']
                print(f'New key {key}')
                main(key)
    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Forti Logs.",
        }),
    }
