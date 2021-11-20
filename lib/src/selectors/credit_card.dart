import 'package:settings_yaml/settings_yaml.dart';

import 'selector.dart';

/// Checks if a log line contains a credit card no. that
/// passes a lunh check.
class CreditCard extends Selector {
  static String type = 'creditcard';

  late final ccRegEx = RegExp(r'(\d{16}\d*)');

  CreditCard.fromMap(SettingsYaml settings, String location)
      : super.fromMap(settings, location);

  /// Check if the line contains a 16 digit CC.
  @override
  Selection matches(String line) {
    /// remove potential spaces between the cc digits.
    line = line.replaceAll('.- ', '');

    // check if we have 16 character no. in the line.
    final matches = ccRegEx.allMatches(line);
    if (matches.isEmpty) {
      return selection(matched: false);
    }

    for (final match in matches) {
      for (var group = 1; group < match.groupCount + 1; group++) {
        final potenticalCC = match.group(group)!;

        if (isLunh(potenticalCC)) {
          return selection(matched: true);
        }
      }
    }
    return selection(matched: false);
  }

  bool isLunh(String potentialCC) {
    if (potentialCC.length != 16) return false;
    // Luhn algorithm
    int sum = 0;
    String digit;
    bool shouldDouble = false;

    for (int i = potentialCC.length - 1; i >= 0; i--) {
      digit = potentialCC.substring(i, (i + 1));
      int tmpNum = int.parse(digit);

      if (shouldDouble == true) {
        tmpNum *= 2;
        if (tmpNum >= 10) {
          sum += ((tmpNum % 10) + 1);
        } else {
          sum += tmpNum;
        }
      } else {
        sum += tmpNum;
      }
      shouldDouble = !shouldDouble;
    }

    return (sum % 10 == 0);
  }

  @override
  String getType() => type;
}
