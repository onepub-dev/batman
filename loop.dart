/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import 'package:dcli/dcli.dart';

void main() {
  for (var i = 0; i < 10000; i++) {
    '/tmp/f9dbeede-fbbc-4c93-9532-9f2f9261df73.tmp'.append('hi $i');
  }
}
