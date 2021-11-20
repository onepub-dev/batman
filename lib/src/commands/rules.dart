import 'package:args/command_runner.dart';
import '../rules.dart';

class RuleCheckCommand extends Command<void> {
  @override
  void run() {
    RuleLogger().showWarnings = true;
    Rules.load();
  }

  @override
  String get description => 'Checks that the rules.yaml file is valid.';

  @override
  String get name => 'rules';
}
