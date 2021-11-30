import 'package:batman/src/rules/matched.dart';
import 'package:batman/src/rules/selectors/selector.dart';

import 'grouped_source_analyser.dart';
import 'source_analyser_mixin.dart';
import '../log_sources/log_source.dart';
import '../log_sources/njcontact_log_source.dart';

class NJContactAnalyser extends GroupedSourceAnalyser
    with SourceAnalyserMixin, GroupedSourceAnalyserMixin {
  bool _resetOccured = false;

  @override
  String preProcessLine(LogSource source, String line, int lineNo) {
    return line;
  }

  @override
  List<Matched> testForMatches(LogSource logSource, String line, int lineNo) {
    /// If we see the nj-contact start message then reset the counts.
    if (line.contains(NJContactLogSource.startMessage)) {
      reset();
      _resetOccured = true;
      return <Matched>[];
    }

    return super.testForMatches(logSource, line, lineNo);
  }

  @override
  String getGroup(String line, Selector selector) {
    String? key;
    final match = RegExp(r'\(.*?\.java\:.*?\)').firstMatch(line);
    if (match != null) {
      key = match[0];
    }
    return key ?? selector.description;
  }

  @override
  StringBuffer prepareReport(LogSource source, StringBuffer sb) {
    if (_resetOccured) {
      sb.writeln('');
      sb.writeln('Encountered tomcat restart in logs, discarded prior logs.');
      sb.writeln('');
    }
    return super.prepareReport(source, sb);
  }
}
