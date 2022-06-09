/* Copyright (C) S. Brett Sutton - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 * Written by Brett Sutton <bsutton@onepub.dev>, Jan 2022
 */

import '../log_scanner/log_sources/log_source.dart';
import 'rule.dart';

import 'selectors/selector.dart';

class Matched {
  Matched(this.source, this.rule, this.selector);
  final LogSource source;
  final Rule rule;
  final Selector selector;
}
