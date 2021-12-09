import 'package:batman/src/rules/risk.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:batman/src/rules/selectors/selector.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('contains with continue', ()  {
    const rulesDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker
        type: contains
        match: ["Locker"]
        exclude: ["Key"]
        risk: medium
    
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: rulesDef, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;

      final contains = rule.selectors.selectors.first;
      expect(contains.risk, equals(Risk.medium));
      expect(contains, isA<Contains>());
      if (contains is Contains) {
        expect(contains.getType(), equals('contains'));
        expect(contains.description, equals('Locker'));
        expect(contains.insensitive, isFalse);
        expect(contains.match, orderedEquals(<String>['Locker']));
        expect(contains.exclude, orderedEquals(<String>['Key']));

        expect(contains.terminate, isFalse);

        expect(contains.matches('Locker'), Selection.matchContinue);
        expect(contains.matches('Nocker'), Selection.nomatch);
        expect(contains.matches('Locker Key'), Selection.nomatch);
        expect(contains.matches('Locker'), Selection.matchContinue);
      }
    });
  });

  test('contains with terminate', ()  {
    const ruleDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker
        type: contains
        continue: false
        match: ["Locker"]
        exclude: ["Key"]
        risk: medium
        
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;

      final contains = rule.selectors.selectors.first;
      expect(contains.risk, equals(Risk.medium));

      expect(contains, isA<Contains>());
      if (contains is Contains) {
        expect(contains.getType(), equals('contains'));
        expect(contains.description, equals('Locker'));
        expect(contains.insensitive, isFalse);
        expect(contains.match, orderedEquals(<String>['Locker']));
        expect(contains.exclude, orderedEquals(<String>['Key']));

        expect(contains.terminate, isTrue);

        expect(contains.matches('Locker'), Selection.matchTerminate);
        expect(contains.matches('Nocker'), Selection.nomatch);
        expect(contains.matches('Locker Key'), Selection.nomatch);
        expect(contains.matches('Locker'), Selection.matchTerminate);
      }
    });
  });

  test('contains case-insensitive', ()  {
    const ruleDef = '''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker
        type: contains
        match: ["Locker"]
        exclude: ["Key"]
        insensitive: true
        continue: false
        risk: none
''';

    withTempFile((path) {
      final settings =
          SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;

      final contains = rule.selectors.selectors.first;
      expect(contains.risk, equals(Risk.none));

      expect(contains, isA<Contains>());
      if (contains is Contains) {
        expect(contains.getType(), equals('contains'));
        expect(contains.description, equals('Locker'));
        expect(contains.insensitive, isTrue);
        expect(contains.match, orderedEquals(<String>['locker']));
        expect(contains.exclude, orderedEquals(<String>['key']));
        expect(contains.terminate, isTrue);

        expect(contains.matches('locker'), Selection.matchTerminate);
        expect(contains.matches('nocker'), Selection.nomatch);
        expect(contains.matches('LOCKER KEY'), Selection.nomatch);
        expect(contains.matches('LOCKER'), Selection.matchTerminate);
      }
    });
  });
}
