/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:intl/intl.dart';

String get when {
  final formatter = DateFormat('yyyy-MM-dd hh:mm');
  return formatter.format(DateTime.now());
}
