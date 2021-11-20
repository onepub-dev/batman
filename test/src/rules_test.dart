import 'package:dcli/dcli.dart' hide equals;
import 'package:pci_file_monitor/src/rules.dart';
import 'package:pci_file_monitor/src/selectors/selector.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('rules ...', () async {
    withTempFile((pathToSettings) {
      final settings =
          SettingsYaml.fromString(content: _rules, filePath: pathToSettings);
      final rules = Rules.loadFromSettings(settings, showWarnings: true);

      /// Check global selector loaded.
      final globalSelectors = rules.logAudits.globalSelectors;
      expect(globalSelectors.length, equals(1));
      final creditCard = globalSelectors[0];
      expect(creditCard.description,
          equals('checks that credit cards are not logged.'));
      expect(creditCard.risk, equals(Risk.critical));
      expect(creditCard.terminate, isFalse);

      // log sources
      final sources = rules.logAudits.sources;
      expect(sources.length, equals(2));
      final selector = sources[0].selectors[0];
      expect(selector is Contains, isTrue);
      final frequency = selector as Contains;
      expect(frequency.description, equals('Frequency'));
      expect(frequency.match, orderedEquals(<String>[' ']));
      expect(frequency.risk, equals(Risk.low));
      expect(frequency.terminate, isFalse);
    });
  });
}

const _rules = '''
log_audits:
  # global selectors apply to every log_source
  global_selectors:
    - selector:
      description: checks that credit cards are not logged.
      type: creditcard
      risk: critical

  log_sources:
  - log_source:
    type: njcontact
    top: 10
    selectors: 
      - selector: 
        type: contains
        description: Frequency
        purpose: I have no idea
        match: [" "]
        risk: low
  - log_source:
    type: njcontact
    top: 1000
    trim_prefix: ':::'
    selectors:
      - selector:
        description: ignore deleterious lines
        type: contains
        continue: false
        match: 
          - 'AgiHangupException'
          - 'Setting logging level to'
          - 'com.mysql.cj.'
          - 'RejectedExecutionHandlerImpl'
          - 'Logs begin at'
          - 'LoggingOutputStream'
      - selector:
        description: jvm pause
        type: contains
        match: 
          - jvm pause
        risk: medium
      - selector:
        description: Locker
        type: contains
        match: 
          - Locker
        risk: medium
      - selector:
        description: Slow
        type: contains
        match: 
          - Slow
        risk: low
      - selector:
        description: OutOfMemory
        type: contains
        match: 
          - Terminating due to java.lang.OutOfMemoryError
        risk: high
      - selector:
        description: Wrong lead trying to save!
        type: contains
        match: 
          - Unable to save changes (Wrong or no lead)
        risk: high
      - selector:
        description: Errors
        type: one_of
        match: ['ERROR']
        exclude: ['Erroneous']
        risk: high
      - selector:
        description: Warning
        type: one_of
        match: ['Warning']
        risk: medium
''';
