import sys
sys.path.append("../../alerts/")

from lib.config import LOGGING, ES

from alert_helper import TestHelper

class ParentTestAlert:
    def setup(self):
        print "Setting up the test environment with " + ES['servers'][0]
        self.helper = TestHelper(ES['servers'][0])

        self.helper.delete_index_if_exists("events")
        self.helper.delete_index_if_exists("events-previous")
        self.helper.delete_index_if_exists("alerts")

        for event in self.events():
            self.helper.event_to_es(event, "events")
            self.helper.event_to_es(event, "events-previous")

    def teardown(self):
        print "Tearing down environment"
        self.helper.delete_index_if_exists("events")
        self.helper.delete_index_if_exists("events-previous")
        self.helper.delete_index_if_exists("alerts")

    def generate_default_event(self):
      current_timestamp = self.helper.current_timestamp()

      source_ip = self.helper.random_ip()
      null = "NIL"

      event =   {
        "category": "brointel",
        "processid": "0",
        "receivedtimestamp": current_timestamp,
        "severity": "7",
        "utctimestamp": current_timestamp,
        "timestamp": current_timestamp,
        "hostname": "nsmserver1",
        "summary": "MozillaHTTPErrors::Excessive_HTTP_Errors_Attacker Excessive HTTP errors for requests from " + source_ip + " 1604 in 15.0 mins, eps: 0",
        "eventsource": "nsm",
        "details": {
          "uid": "",
          "actions": "Notice::ACTION_LOG",
          "fuid": "",
          "dropped": "F",
          "sub": "1604 in 15.0 mins, eps: 0",
          "proto": "",
          "dst": "",
          "note": "MozillaHTTPErrors::Excessive_HTTP_Errors_Attacker",
          "sourceipv4address": source_ip,
          "peer_descr": "nsm14-p1p1-20",
          "sourceipgeolocation": {
            "city": null,
            "region_code": null,
            "area_code": 0,
            "time_zone": "Europe/Berlin",
            "dma_code": 0,
            "metro_code": null,
            "country_code3": "DEU",
            "country_name": "Germany",
            "postal_code": null,
            "longitude": 9,
            "country_code": "DE",
            "latitude": 51,
            "continent": "EU"
          },
          "destinationport": 0,
          "msg": "Excessive HTTP errors for requests from " + source_ip,
          "destinationipaddress": "0.0.0.0",
          "sourceport": 0,
          "sourceipaddress": source_ip,
          "src": source_ip,
          "n": "",
          "p": "",
          "file_mime_type": "",
          "file_desc": "",
          "destinationipv4address": "0.0.0.0",
          "suppress_for": "900.000000"
        }
      }

      return event

    def test_alert(self):
        # THIS IS A HAX, todo: modify this to call celery with syncronous execution
        import time
        time.sleep(2)

        alert_instance = self.alert_class()()
        alert_instance.run()
        self.alert_task = alert_instance

        self.verify_alert()


    def verify_alert_not_fired(self):
        alert = self.alert_task.alert
        assert alert == None
