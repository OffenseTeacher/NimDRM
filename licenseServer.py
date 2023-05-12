from flask import Flask, json, request
import random
import string

key = "28CE604DA2F2101F03003D968B4DBF9D5E933E6B" #Replace me
authorized_file_hashes = {"9B6C512D3AAEF5A1F8DDC2AE13209A73CCE8BEEC"} #Make sure payload's on disk SHA1 hash is in this list
authorized_licenses = {"e95a94f6-695e-4418-90ef-f07bb3e75025"} #Make sure the license used in NimDRM is in this list
registered_licenses = []
banned_licenses = []
bad_response = {"key":"","secret":""}

api = Flask(__name__)
def generate_secret():
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(128))
    return result_str

@api.route('/authorize', methods=['POST'])
def authorize():
  request_data = request.get_json(force=True)
  license = request_data["license"]
  file_hash = request_data["file_hash"].upper()
  host = request_data["host"]
  secret = request_data["secret"]
  if license in banned_licenses or license not in authorized_licenses:
    print("Received banned or unknown license: " + license)
    return json.dumps(bad_response)
  
  if license in authorized_licenses and file_hash not in authorized_file_hashes:
    banned_licenses.append(license)
    print("Received unauthorized file hash. Banning license: " + license)
    return json.dumps(bad_response)
  
  for registered_license in registered_licenses:
      if registered_license["license"] == license:
          if registered_license["host"] != host or registered_license["secret"] != secret:
              banned_licenses.append(license)
              print("Received invalid host or secret. Banning license: " + license)
              return json.dumps(bad_response)
          else:
              #known good execution
              print("Received valid request, returning encryption key")
              return {"key": key, "secret": registered_license["secret"]}
  
  #first time execution
  print("License " + license + " is now authorized")
  secret = generate_secret()
  registered_licenses.append({"license": license, "host": host, "secret": secret})
  return {"key": key, "secret": secret}

  

  return json.dumps(response)

if __name__ == '__main__':
    api.run(host='0.0.0.0') 