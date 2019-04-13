import boto3
import os


def upload_photo(folder_name, user_name):
    client = boto3.client('s3')
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, 'static/avatar.jpg'), 'rb') as f:
        photo_stream = f.read()
        response = client.put_object(ACL='public-read', Body=photo_stream,
                                     Bucket='ece1779avatar', Key=folder_name + str(user_name) + '.jpg',
                                     ContentType='image/jpeg')
    return response

def copy_photo(bucket_name,user_name, source_file_name, folder_name):
    client = boto3.client('s3')
    response = client.copy_object(ACL='public-read', Bucket='ece1779avatar',
                                  CopySource={'Bucket': bucket_name, 'Key': source_file_name},
                                  Key=folder_name + str(user_name) + '.jpg',
                                  ContentType='image/jpeg')
    return response
