/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:batman/src/commands/logs.dart';
import 'package:batman/src/parsed_args.dart';
import 'package:test/test.dart';

void main() {
  test('health check ...', () {
    ParsedArgs.withArgs(['--insecure']);
    LogsCommand().run();
  });
}
