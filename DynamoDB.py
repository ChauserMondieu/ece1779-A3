import boto3
import json


def put_item(table_name, key_name, key_value, attribute, attribute_type, attribute_value):
    client = boto3.client('dynamodb')
    client.put_item(TableName=table_name, Item={key_name: {"S": key_value}, attribute: {attribute_type: attribute_value}})


def get_item(table_name, key_name, key_value, attribute, attribute_type):
    client = boto3.client('dynamodb')
    response = client.get_item(TableName=table_name, Key={key_name: {"S": key_value}}, AttributesToGet=[attribute])
    return response['Item'][attribute][attribute_type]


def scan_table(attribute, attribute_type, attribute_value):
    client = boto3.client('dynamodb')
    response = client.scan(TableName='People', ScanFilter={attribute: {'AttributeValueList': [{attribute_type: attribute_value}], 'ComparisonOperator': 'EQ'}})
    return response['Items'], response['Count']


def delete_item(user_name):
    client = boto3.client('dynamodb')
    client.delete_item(TableName='People', Key={'user_name': {"S": user_name}})



def get_all_items(table_name,attribute_name):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    response = table.scan()

    nameList = []
    for i in response['Items']:
        nameList.append(i[attribute_name])

    return nameList


