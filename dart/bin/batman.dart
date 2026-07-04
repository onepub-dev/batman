#! /usr/bin/env dcli
/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:batman/src/entry_point.dart';
import 'package:batman/src/version/version.g.dart';

void main(List<String> arguments) async {
  print('Batman $packageVersion');
  await run(arguments);
}
