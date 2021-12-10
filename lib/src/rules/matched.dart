import '../log_scanner/log_sources/log_source.dart';
import 'rule.dart';

import 'selectors/selector.dart';

class Matched {
  Matched(this.source, this.rule, this.selector);
  final LogSource source;
  final Rule rule;
  final Selector selector;
}