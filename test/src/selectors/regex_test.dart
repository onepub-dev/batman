import 'package:batman/src/rules/risk.dart';
import 'package:batman/src/rules/rules.dart';
import 'package:batman/src/rules/selectors/regex.dart';
import 'package:batman/src/rules/selectors/selector.dart';
import 'package:dcli/dcli.dart' hide equals;
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('contains with continue', () async {
    final ruleDef = r'''
log_audits:
  rules:
    - rule:
      name: locker
      selectors: 
      - selector:
        description: Locker
        type: regex
        match: ["L\\w*r"]
        exclude: ["K\\wy"]
        risk: medium
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: ruleDef, filePath: path);

      final rules = Rules.fromMap(settings);

      final rule = rules.rules.first;

      final regex = rule.selectors.selectors.first;
      expect(regex.risk, equals(Risk.medium));
      expect(regex, isA<RegEx>());
      if (regex is RegEx) {
        expect(regex.getType(), equals('regex'));
        expect(regex.description, equals('Locker'));
        expect(regex.match, orderedEquals(<RegExp>[RegExp(r'L\w*r')]));
        expect(regex.exclude, orderedEquals(<RegExp>[RegExp(r'K\wy')]));
        expect(regex.terminate, isFalse);

        expect(regex.matches('Locker'), Selection.matchContinue);
        expect(regex.matches('Nocker'), Selection.nomatch);
        expect(regex.matches('Locker Key'), Selection.nomatch);
        expect(regex.matches('Locker'), Selection.matchContinue);
      }
    });
  });
}
