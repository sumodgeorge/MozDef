import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "../../alerts"))


## ALERT SOURCE START
from lib.alerttask import AlertTask
import pyes

class AggregatedExampleAlert(AlertTask):

    def main(self):
        date_timedelta = dict(minutes=2)
        must = [
            pyes.TermFilter('_type', 'event'),
            pyes.TermFilter('category', 'brointel'),
        ]
        self.filtersManual(date_timedelta, must=must)

        self.searchEventsAggregated('details.sourceipaddress', samplesLimit=3)
        self.walkAggregations(threshold=2)

    # Set alert properties
    def onEvent(self, event):
        category = 'TESTCATEGORY'
        tags = ['test']
        severity = 'INFO'

        summary = "Test Summary here"

        return self.createAlertDict(summary, category, tags, [event], severity)

    def onAggregation(self, aggreg):
        # aggreg['count']: number of items in the aggregation, ex: number of failed login attempts
        # aggreg['value']: value of the aggregation field, ex: toto@example.com
        # aggreg['events']: list of events in the aggregation
        category = 'bruteforce'
        tags = ['test']
        severity = 'NOTICE'

        summary = "Aggregated results summary"

        return self.createAlertDict(summary, category, tags, aggreg['events'], severity)
## ALERT SOURCE END


from parent_test_alert import ParentTestAlert

class TestAggregatedAlertExists(ParentTestAlert):
    def alert_class(self):
        return AggregatedExampleAlert

    def events(self):
        events = []
        for a in range(1, 5):
          event = self.generate_default_event()
          event['details']['sourceipaddress'] = '2.2.3.4'
          events.append(event)

        return events

    def verify_alert(self):
        alert = self.alert_task.alert

        assert len(alert['events']) == 3

        for events in alert['events']:
          for event_alert in events['documentsource']['alerts']:
            found_alert = self.helper.get_alert_by_id(event_alert['id'])
            assert found_alert['found'] == True
            assert found_alert['_source']['category'] == 'bruteforce'
            assert len(found_alert['_source']['events']) == 3
            assert found_alert['_source']['severity'] == 'NOTICE'
            assert found_alert['_source']['summary'] == 'Aggregated results summary'
            assert found_alert['_source']['tags'] == ['test']
            # Why is this unicode???
            assert type(found_alert['_source']['utctimestamp']) == unicode


class TestAggregatedAlertDoesntExist(ParentTestAlert):
    def alert_class(self):
        return AggregatedExampleAlert


    def events(self):
        events = []
        for a in range(1, 1):
          event = self.generate_default_event()
          event['details']['sourceipaddress'] = '2.2.3.4'
          events.append(event)

        return events

    def verify_alert(self):
        self.verify_alert_not_fired()
