import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../alerts"))

from parent_test_alert import ParentTestAlert

from duo_fail_open import AlertDuoFailOpen

class ParentDuoFailOpenTest(ParentTestAlert):
    def alert_class(self):
        return AlertDuoFailOpen

    def generate_default_event(self):
        current_timestamp = self.helper.current_timestamp()

        source_ip = self.helper.random_ip()
        destination_ip = self.helper.random_ip()
        null = "NIL"

        event = {
            "category": "duo",
            "processid": "0",
            "receivedtimestamp": current_timestamp,
            "severity": "7",
            "utctimestamp": current_timestamp,
            "timestamp": current_timestamp,
            "hostname": "duo_host",
            "summary": "Failsafe Duo login summary",
            "eventsource": "duo_eventsource",
            "details": {
              "src": source_ip,
              "sourceipaddress": source_ip,
              "sub": "",
              "proto": "tcp",
              "dst": destination_ip,
              "destinationipaddress": destination_ip,
              "actions": "Notice::ACTION_LOG",
              "n": "",
              "note": "Duo Login Note",
              "p": "1005",
              "sourceipv4address": source_ip,
              "fuid": "",
              "dropped": "F",
              "msg": "Duo Login Note",
              "peer_descr": "duo_host",
              "file_mime_type": "",
              "file_desc": "",
              "uid": "asbsdclahsdf11414",
              "destinationipv4address": destination_ip,
              "suppress_for": "1.000000",
              "hostname": "duo_host",
            }
        }

        return event

class TestDuoFailOpenPositive(ParentDuoFailOpenTest):
    def events(self):
        events = []
        for a in range(1, 15):
            event = self.generate_default_event()
            events.append(event)

        return events

    def verify_alert(self):
        alert = self.alert_task.alert

        assert len(alert['events']) == 10

        for events in alert['events']:
          for event_alert in events['documentsource']['alerts']:
            found_alert = self.helper.get_alert_by_id(event_alert['id'])
            assert found_alert['found'] == True
            assert found_alert['_source']['category'] == 'bypass'
            assert len(found_alert['_source']['events']) == 10
            assert found_alert['_source']['severity'] == 'WARNING'
            assert found_alert['_source']['summary'] == 'DuoSecurity contact failed, fail open triggered on duo_host'
            assert found_alert['_source']['tags'] == ['openvpn', 'duosecurity']
            # Why is this unicode???
            assert type(found_alert['_source']['utctimestamp']) == unicode


class TestDuoFailOpenMissingHostname(ParentDuoFailOpenTest):
    def events(self):
        events = []
        for a in range(1, 15):
            event = self.generate_default_event()
            event['details'].pop('hostname')
            events.append(event)

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


class TestDuoFailOpenIncorrectSummary(ParentDuoFailOpenTest):
    def events(self):
        events = []
        for a in range(1, 15):
            event = self.generate_default_event()
            event['summary'] = "Example test summary"
            events.append(event)

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


