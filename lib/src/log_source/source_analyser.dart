/// an interface for [LogSource]s designed
/// to allow them to collate data across the logs
abstract class SourceAnalyser {
  bool get reset => false;

  /// called each time we read a line from the source
  void process(String line);
}

class NoopAnalyser implements SourceAnalyser {
  @override
  void process(String line) {}

  @override
  bool get reset => false;
}
