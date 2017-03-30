import os, shutil, tarfile
import json
from google.cloud.storage import Blob



# delete directory
def remove_dir(path):
    for the_file in os.listdir(path):
        file_path = os.path.join(path, the_file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(e)
    if os.path.exists(path+'/'):
        shutil.rmtree(path+'/')

def check_if_dir_exists(path):
    d=os.path.dirname(path);
    if not os.path.exists(d):
        os.makedirs(d)

def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))

# load json config file
def load_cf_file(cf_filename):
    with open(cf_filename) as cf:
        data = json.load(cf)
    return data;

def archive_vuln(path, repo):
    with open(path, 'wb') as vv:
        repo.archive(vv)

def send_blob(path, vpath, bucket):
    blob = Blob(path, bucket)
    with open(vpath, 'rb') as f:
        blob.upload_from_file(f)
