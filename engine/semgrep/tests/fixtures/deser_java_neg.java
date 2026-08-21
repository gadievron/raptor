import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

public class Loader {
    Object loadConfig(String doc) {
        Yaml y = new Yaml(new SafeConstructor(new LoaderOptions()));
        return y.load(doc);
    }

    void configure(com.fasterxml.jackson.databind.ObjectMapper mapper) {
        mapper.activateDefaultTyping(
            com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator.builder().build());
    }
}
