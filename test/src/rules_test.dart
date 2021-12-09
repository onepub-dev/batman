import 'package:batman/src/batman_settings.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('rules ...', ()  {
    withTempFile((pathToSettings) {
      final settings =
          SettingsYaml.fromString(content: _rules, filePath: pathToSettings);
      final rules =
          BatmanSettings.loadFromSettings(settings, showWarnings: true);

      // log sources
      final sources = rules.logAudits.sources;
      expect(sources.length, equals(3));
      expect(sources[0].ruleReferences.rules.length, equals(2));
      final selector = sources[0].ruleReferences.rules[0];
      expect(selector.name, equals('integrity check'));
    });
  });
}

const _rules = '''
log_audits:
  log_sources:
    - log_source:
      description: File Integrity logs
      type: file
      top: 1000
      path: /var/log/batman.log
      trim_prefix: ':::'
      rules:
        - rule: integrity check
        - rule: errors
      
        
    - log_source:
      type: njcontact
      description: Group Logging lines - by java source and line no.
      top: 10
      reset: Starting Servlet engine
      rules:
        - rule: njcontact-frequency


    - log_source:
      type: njcontact
      description: Noojee Contact logs
      top: 1000
      reset: Starting Servlet engine
      trim_prefix: ':::'
      rules:
        - rule: creditcard
        - rule: errors
        - rule: njcontact
          

      
  rules:
    - rule:
      name: creditcard
      description: Scans for credit cards 
      selectors:
        - selector:
          type: creditcard
          description: A credit card was detected in a log file
          risk: critical
    - rule:
      name: integrity check
      description: Scans the file integrity logs for issues
      selectors:
        - selector:
          type: contains
          description: The contents of a file has changed which may indicate an intruder.
          match: ['Integrity:']
          risk: critical
          continue: false
        - selector:
          description: A baseline scan failed to process a file due to permission denied.
          type: contains
          match: ['permission denied']
          risk: medium
          continue: false

    - rule:
      name: errors
      description: Scans for general errors and warnings.
      selectors:
        - selector:
          type: contains
          description: An error was detected
          match: ['Error']
          risk: high
          continue: false
        - selector:
          type: contains
          description: a warning was detected
          match: ['Warning']
          risk: medium
          continue: false
      
    - rule:
      name: njcontact-frequency
      description: Need to ask robert what this was meant to do?
      selectors:
        - selector:
          description: I have no idea
          type: contains
          match: [" "]
          risk: low
      
    - rule:
      name: njcontact
      description: errors specific to the noojee contact log source
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
          risk: none
        - selector:
          description: The java VM is pausing excessively due to GC.
          type: contains
          match: ["jvm pause"]
          risk: medium
        - selector:
          description: Locker
          type: contains
          match: ["Locker"]
          risk: medium
        - selector:
          description: Slow
          type: contains
          match: ["Slow"]
          risk: low
        - selector:
          description: Java is reporting an out of memory condition
          type: contains
          match: ["Terminating due to java.lang.OutOfMemoryError"]
          risk: high
        - selector:
          description: Saving a lead failed due to a wrong or no lead.
          type: contains
          match: ["Unable to save changes (Wrong or no lead)"]
          risk: high

''';
