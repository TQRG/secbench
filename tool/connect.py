from utils import *
from github import *
import redis
from google.cloud import storage

# connect to the database
def connect_to_db(cf_filename):
    try:
        redis_cf = load_cf_file(cf_filename)
        # redis connection
        r = redis.Redis(
            host=redis_cf['redis']['host'],
            port=redis_cf['redis']['port'],
            password=redis_cf['redis']['password'])
        print('Succesfully connected to the database!')
        return r;
    except Exception as ex:
        print 'Error:', ex
        exit('Failed to connect, terminating.')

# connect to github
def connect_to_github(cf_filename):
    try:
        data = load_cf_file(cf_filename)
        # authentication for Github API
        g = Github(data['github']['username'], data['github']['token'])
        print('Succesfully connected to github!')
        return g;
    except BadCredentialsException as ex:
        print 'Error:', ex
        exit('\nSomething went wrong, check your GitHub credentials on the config.json file.')

def connect_to_gcloud_storage():
    storage_client = storage.Client()
    return storage_client;

def get_bucket(storage_client, bucket_name):
    try:
        bucket = storage_client.get_bucket(bucket_name)
    except google.cloud.exceptions.NotFound:
        print('Sorry, that bucket does not exist!')
    return bucket;
