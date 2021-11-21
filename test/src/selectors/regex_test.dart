import 'package:dcli/dcli.dart' hide equals;
import 'package:batman/src/selectors/regex.dart';
import 'package:batman/src/selectors/selector.dart';
import 'package:settings_yaml/settings_yaml.dart';
import 'package:test/test.dart';

void main() {
  test('contains with continue', () async {
    final rules = r'''
log_audits:
  log_sources:
  - log_source:
    selectors: 
    - selector:
      description: Locker
      type: regex
      match: ["L\\w*r"]
      exclude: ["K\\wy"]
      risk: medium
''';

    withTempFile((path) {
      var settings = SettingsYaml.fromString(content: rules, filePath: path);

      final regex = RegEx.fromMap(settings,
          'log_audits.log_sources.log_source[0].selectors.selector[0]');

      expect(regex.getType(), equals('regex'));
      expect(regex.description, equals('Locker'));
      expect(regex.match, orderedEquals(<RegExp>[RegExp(r'L\w*r')]));
      expect(regex.exclude, orderedEquals(<RegExp>[RegExp(r'K\wy')]));
      expect(regex.risk, equals(Risk.medium));
      expect(regex.terminate, isFalse);

      expect(regex.matches('Locker'), Selection.matchContinue);
      expect(regex.matches('Nocker'), Selection.nomatch);
      expect(regex.matches('Locker Key'), Selection.nomatch);
      expect(regex.matches('Locker'), Selection.matchContinue);
    });
  });
}
