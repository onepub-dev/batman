/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'selector.dart';

/// Checks if a log line contains a credit card no. that
/// passes a lunh check.
class CreditCard extends Selector {
  CreditCard.fromMap(super.settings, super.location) : super.fromMap();
  static String type = 'creditcard';

  late final ccRegEx = RegExp(r'(\d{16}\d*)');

  /// Check if the line contains a 16 digit CC.
  @override
  Selection matches(String line) {
    /// remove potential spaces between the cc digits.
    final _line = line.replaceAll('.- ', '');

    // check if we have 16 character no. in the line.
    final matches = ccRegEx.allMatches(_line);
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
    if (potentialCC.length != 16) {
      return false;
    }
    // Luhn algorithm
    var sum = 0;
    String digit;
    var shouldDouble = false;

    for (var i = potentialCC.length - 1; i >= 0; i--) {
      digit = potentialCC.substring(i, i + 1);
      var tmpNum = int.parse(digit);

      if (shouldDouble == true) {
        tmpNum *= 2;
        if (tmpNum >= 10) {
          sum += (tmpNum % 10) + 1;
        } else {
          sum += tmpNum;
        }
      } else {
        sum += tmpNum;
      }
      shouldDouble = !shouldDouble;
    }

    return sum % 10 == 0;
  }

  @override
  String sanitiseLine(String line) =>
      line.replaceAll(ccRegEx, 'XXXX XXXX XXXX XXXX');

  @override
  String getType() => type;
}
