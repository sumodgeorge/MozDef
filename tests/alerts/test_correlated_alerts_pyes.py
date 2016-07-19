import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../alerts"))

from parent_test_alert import ParentTestAlert
from correlated_alerts_pyes import AlertCorrelatedIntelNotice

class ParentCorrelatedIntelNoticeTest(ParentTestAlert):
    def alert_class(self):
        return AlertCorrelatedIntelNotice

    def event_type(self):
        return 'bro'

    def generate_default_event(self):
        current_timestamp = self.helper.current_timestamp()

        source_ip = self.helper.random_ip()
        destination_ip = self.helper.random_ip()
        null = "NIL"

        event = {
            "category": "bronotice",
            "processid": "0",
            "receivedtimestamp": current_timestamp,
            "severity": "7",
            "utctimestamp": current_timestamp,
            "timestamp": current_timestamp,
            "hostname": "nsm1",
            "summary": "CrowdStrike::Correlated_Alerts Host " + source_ip + " caused an alert to throw",
            "eventsource": "nsm",
            "details": {
              "src": source_ip,
              "sourceipaddress": source_ip,
              "sub": "",
              "proto": "tcp",
              "dst": destination_ip,
              "destinationipaddress": destination_ip,
              "actions": "Notice::ACTION_LOG",
              "n": "",
              "note": "CrowdStrike::Correlated_Alerts",
              "p": "1005",
              "sourceipv4address": source_ip,
              "fuid": "",
              "dropped": "F",
              "msg": "Example Correlated_Alerts alert",
              "peer_descr": "nsm",
              "file_mime_type": "",
              "file_desc": "",
              "uid": "asbsdclahsdf11414",
              "destinationipv4address": destination_ip,
              "suppress_for": "1.000000"
            }
        }

        return event

class TestCorrelatedIntelNoticePositive(ParentCorrelatedIntelNoticeTest):
    def events(self):
        event = self.generate_default_event()
        source_ip = "1.2.3.4"
        event['summary'] = "CrowdStrike::Correlated_Alerts Host " + source_ip + " caused an alert to throw"
        event['details']['src'] = source_ip
        event['details']['sourceipaddress'] = source_ip
        event['details']['sourceipv4address'] = source_ip

        events = [event]

        return events

    def verify_alert(self):
        alert = self.alert_task.alert

        assert len(alert['events']) == 1

        for events in alert['events']:
          for event_alert in events['documentsource']['alerts']:
            found_alert = self.helper.get_alert_by_id(event_alert['id'])
            assert found_alert['found'] == True
            assert found_alert['_source']['category'] == 'correlatedalerts'
            assert len(found_alert['_source']['events']) == 1
            assert found_alert['_source']['severity'] == 'NOTICE'
            assert found_alert['_source']['summary'] == 'nsm1 CrowdStrike::Correlated_Alerts Host 1.2.3.4 caused an alert to throw'
            assert found_alert['_source']['tags'] == ['nsm,bro,correlated']
            assert found_alert['_source']['url'] == "https://mana.mozilla.org/wiki/display/SECURITY/NSM+IR+procedures"
            # Why is this unicode???
            assert type(found_alert['_source']['utctimestamp']) == unicode


class TestCorrelatedIntelNoticeAsEventType(ParentCorrelatedIntelNoticeTest):
    def event_type(self):
        return "event"

    def events(self):
        event = self.generate_default_event()
        source_ip = "82.204.142.44"
        event['summary'] = "CrowdStrike::Correlated_Alerts Host " + source_ip + " caused an alert to throw"
        event['details']['src'] = source_ip
        event['details']['sourceipaddress'] = source_ip
        event['details']['sourceipv4address'] = source_ip

        events = [event]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()

class TestCorrelatedIntelNoticeWithChangedEventSource(ParentCorrelatedIntelNoticeTest):
    def events(self):
        event = self.generate_default_event()
        event['eventsource'] = "syslog"

        events = [event]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


class TestCorrelatedIntelNoticeWithChangedCategory(ParentCorrelatedIntelNoticeTest):
    def events(self):
        event = self.generate_default_event()
        event['category'] = "brointel"

        events = [event]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


class TestCorrelatedIntelNoticeWithRemovedSourceIP(ParentCorrelatedIntelNoticeTest):
    def events(self):
        event = self.generate_default_event()
        event['details'].pop("sourceipaddress")

        events = [event]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


class TestCorrelatedIntelNoticeWithUnmatchedNote(ParentCorrelatedIntelNoticeTest):
    def events(self):
        event = self.generate_default_event()
        event['details']['note'] = 'ConnAnomaly::ConnLong'

        events = [event]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()
