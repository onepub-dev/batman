import '../../rules/matched.dart';
import '../../rules/rule.dart';
import '../../rules/selectors/selector.dart';

import '../log_sources/log_source.dart';
import 'source_analyser.dart';

/// A default [SourceAnalyser] implementation
/// that captures each log line that was matched by a rule selector.
mixin SourceAnalyserMixin implements SourceAnalyser {
  final rules = <Rule, _RuleSelections>{};

  @override
  int matchCount = 0;

  void reset() {
    matchCount = 0;
    rules.clear();
  }

  /// called each time we read a line from the source
  @override
  List<Matched> testForMatches(LogSource logSource, String line, int lineNo) {
    final matches = <Matched>[];

    for (final ruleReference in logSource.ruleReferences.rules) {
      for (final selector in ruleReference.rule.selectors.selectors) {
        final selection = selector.matches(line);

        if (selection == Selection.nomatch) continue;

        matches.add(Matched(logSource, ruleReference.rule, selector));

        if (selection == Selection.matchTerminate) break;
      }
    }

    return matches;
  }

  @override
  String preProcessLine(LogSource source, String line, int lineNo) => line;

  /// called each time a line matches.
  @override
  void processMatch(
      LogSource source, Rule rule, Selector selector, String line, int lineNo) {
    matchCount++;

    var ruleSelections = rules[rule];
    if (ruleSelections == null) {
      rules[rule] = ruleSelections = _RuleSelections(rule);
    }

    ruleSelections.add(_SelectedLine(rule, selector, line, lineNo));
  }

  @override
  StringBuffer prepareReport(LogSource logSource, StringBuffer sb) {
    var reported = 0;
    if (matchCount == 0) {
      sb.writeln('No failures for ${logSource.description}');
    } else {
      sb.writeln(
          '$matchCount events were detected in ${logSource.description}');

      final selections = rules.values.toList();

      for (final selection in selections) {
        sb.writeln(
            'Rule: ${selection.rule.name} - ${selection.rule.description} ');
        selection.selectedLines.sort(sortLine);
        for (final line in selection.selectedLines) {
          if (logSource.top > reported) sb.writeln(line.description);
          reported++;
        }
      }
    }

    return sb;
  }

  int sortLine(_SelectedLine lhs, _SelectedLine rhs) =>
      lhs.selector.risk.index - rhs.selector.risk.index;
}

/// Stores a list of lines against the rule that selected them.
class _RuleSelections {
  _RuleSelections(this.rule);
  final Rule rule;
  final selectedLines = <_SelectedLine>[];

  void add(_SelectedLine selectedLine) => selectedLines.add(selectedLine);
}

class _SelectedLine {
  _SelectedLine(this.rule, this.selector, this.line, this.lineNo);
  final Rule rule;
  final Selector selector;

  /// the line no. within the log source that generated this line.
  final int lineNo;
  final String line;

  String get description => line;
}
