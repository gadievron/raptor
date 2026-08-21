import java.beans.XMLDecoder;
import org.yaml.snakeyaml.Yaml;

public class Loader {
    Object loadBean(java.io.InputStream in) {
        XMLDecoder dec = new XMLDecoder(in);
        return dec.readObject();
    }

    Object loadConfig(String doc) {
        Yaml y = new Yaml();
        return y.load(doc);
    }

    void configure(com.fasterxml.jackson.databind.ObjectMapper mapper) {
        mapper.enableDefaultTyping();
    }
}
