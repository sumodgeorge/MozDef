import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../alerts"))


## ALERT SOURCE START
from lib.alerttask import AlertTask
import pyes

class BasicExampleAlert(AlertTask):

    def main(self):
        date_timedelta = dict(minutes=2)
        must = [
            pyes.TermFilter('_type', 'event'),
            pyes.TermFilter('category', 'brointel'),
        ]
        self.filtersManual(date_timedelta, must=must)

        # Search events
        self.searchEventsSimple()
        self.walkEvents()

    # Set alert properties
    def onEvent(self, event):
        category = 'TESTCATEGORY'
        tags = ['test']
        severity = 'INFO'

        summary = "Test Summary here"

        return self.createAlertDict(summary, category, tags, [event], severity)
## ALERT SOURCE END



from parent_test_alert import ParentTestAlert

class TestBasicAlertExists(ParentTestAlert):

    def alert_class(self):
        return BasicExampleAlert

    def events(self):
        events = [
          self.generate_default_event()
        ]

        return events

    def verify_alert(self):
        alert = self.alert_task.alert

        assert len(alert['events']) == 1

        for events in alert['events']:
          for event_alert in events['documentsource']['alerts']:
            found_alert = self.helper.get_alert_by_id(event_alert['id'])
            assert found_alert['found'] == True
            assert found_alert['_source']['category'] == 'TESTCATEGORY'
            assert len(found_alert['_source']['events']) == 1
            assert found_alert['_source']['severity'] == 'INFO'
            assert found_alert['_source']['summary'] == 'Test Summary here'
            assert found_alert['_source']['tags'] == ['test']
            # Why is this unicode???
            assert type(found_alert['_source']['utctimestamp']) == unicode


class TestBasicAlertWithOldTimestampDoesntExist(ParentTestAlert):

    def alert_class(self):
        return BasicExampleAlert

    def events(self):
        default_event = self.generate_default_event()
        custom_timestamp = self.helper.subtract_from_timestamp(self.helper.current_timestamp(), dict(minutes=3))
        default_event['receivedtimestamp'] = custom_timestamp
        default_event['utctimestamp'] = custom_timestamp
        default_event['timestamp'] = custom_timestamp

        events = [
          default_event
        ]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()


class TestBasicAlertWithBadCategoryDoesntExist(ParentTestAlert):

    def alert_class(self):
        return BasicExampleAlert

    def events(self):
        default_event = self.generate_default_event()
        default_event['category'] = "badcategory"

        events = [
          default_event
        ]

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()

