# A simple helper class to insert test events into mozdef

import httplib
import json

import random

from datetime import datetime
from datetime import timedelta
from dateutil.parser import parse
import pytz

class TestHelper():
  def __init__(self, elasticsearch_host):
    self.elasticsearch_host = elasticsearch_host.replace("http://","")

  def event_to_es(self, json_data, index='events'):
    post_data = json.dumps(json_data)
    conn = httplib.HTTPConnection(self.elasticsearch_host)
    conn.request("POST", "/" + index + "/event/", post_data)
    response = conn.getresponse()
    conn.close()
    if response.status == 201:
      print "[+] Successfully inserted into elasticsearch at " + self.elasticsearch_host + " in index " + index
    else:
      print response.status, response.reason

  def delete_index_if_exists(self, index_name):
    conn = httplib.HTTPConnection(self.elasticsearch_host)
    conn.request('DELETE', index_name)
    response = conn.getresponse()
    body = response.read()
    return body

  def get_alert_by_id(self, id):
    conn = httplib.HTTPConnection(self.elasticsearch_host)
    conn.request('GET', "/alerts/alert/" + str(id))
    response = conn.getresponse()

    return json.loads(response.read())

  def random_ip(self):
    return str(random.randint(1, 255)) + "." + str(random.randint(1, 255)) + "." + str(random.randint(1, 255)) + "." + str(random.randint(1, 255))

  def current_timestamp(self):
    return pytz.UTC.normalize(pytz.timezone("UTC").localize(datetime.now())).isoformat()

  def subtract_from_timestamp(self, timestamp, date_timedelta):
    utc_time = parse(timestamp)
    custom_date = utc_time - timedelta(**date_timedelta)

    return custom_date.isoformat()

