import 'package:args/command_runner.dart';
import 'package:batman/src/rules/batman_yaml_logger.dart';
import '../batman_settings.dart';

class RuleCheckCommand extends Command<void> {
  @override
  void run() {
    BatmanYamlLogger().showWarnings = true;
    BatmanSettings.load();
  }

  @override
  String get description => 'Checks that the rules.yaml file is valid.';

  @override
  String get name => 'rules';
}
