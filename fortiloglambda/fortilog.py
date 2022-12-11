import json
import configparser
import os
import boto3
import email

def getconfig():
    config = configparser.ConfigParser()
    config.read('fwloglambda.cfg')
    try:
        logtable = config['loginfo']['logtable']
        actiontable = config['loginfo']['actiontable']
        awsregion = config['loginfo']['awsregion']
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

    configobj = {}
    configobj["logtable"] = logtable
    configobj["awsregion"] = awsregion
    configobj["actiontable"] = actiontable
    return configobj

def getlogdict(msg, logtable, actiontable, awsregion):
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
                table.put_item(TableName=logtable, Item=logdict)
                table.put_item(TableName=actiontable, Item=actiondict)

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
    logdict = getlogdict(msg,configobj["logtable"], configobj["actiontable"], configobj["awsregion"])
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
