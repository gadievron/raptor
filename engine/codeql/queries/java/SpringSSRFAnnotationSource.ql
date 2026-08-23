/**
 * @name SSRF via Spring annotation-driven parameter injection
 * @description Detects server-side request forgery where user input enters
 *              through Spring MVC annotation-injected parameters (@RequestParam,
 *              @PathVariable, @RequestHeader, @RequestBody, @MatrixVariable)
 *              and flows into HTTP client calls without validation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id raptor/java/spring-ssrf-annotation-source
 * @tags security
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.frameworks.spring.SpringController
import semmle.code.java.frameworks.spring.SpringWeb
import semmle.code.java.frameworks.spring.SpringWebClient
import semmle.code.java.frameworks.spring.SpringHttp
import semmle.code.java.frameworks.Networking
import semmle.code.java.frameworks.ApacheHttp
import semmle.code.java.frameworks.javase.Http
import SpringSsrfFlow::PathGraph

/**
 * A parameter on a Spring request-mapping method that carries a
 * servlet-input annotation marking it as directly derived from the
 * HTTP request (query string, path, header, body, or matrix variable).
 */
class SpringAnnotatedInputParameter extends DataFlow::Node {
  SpringAnnotatedInputParameter() {
    exists(Parameter p |
      p = this.asParameter() and
      p.getCallable() instanceof SpringRequestMappingMethod and
      p.getAnAnnotation() instanceof SpringServletInputAnnotation
    )
  }
}

/**
 * Calls on Spring's RestTemplate that accept a URL argument and
 * make an outbound HTTP request.
 */
class RestTemplateCallSink extends DataFlow::Node {
  RestTemplateCallSink() {
    exists(MethodCall mc, Method m |
      mc.getMethod() = m and
      m.getDeclaringType().getAnAncestor() instanceof SpringRestTemplate and
      m.getName() =
        [
          "getForObject", "getForEntity", "postForObject", "postForEntity", "postForLocation",
          "put", "patchForObject", "delete", "exchange", "execute"
        ] and
      // The URL/URI is always the first argument on these methods.
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * `WebClient.create(url)` -- the static factory that takes a base URL.
 */
class WebClientCreateSink extends DataFlow::Node {
  WebClientCreateSink() {
    exists(MethodCall mc, Method m |
      mc.getMethod() = m and
      m.getDeclaringType() instanceof SpringWebClient and
      m.getName() = "create" and
      m.getNumberOfParameters() = 1 and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * `new URL(str).openConnection()` -- the URL constructor is the
 * taint-relevant sink because the string determines the target.
 */
class JavaNetUrlSink extends DataFlow::Node {
  JavaNetUrlSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = cie.getArgument(0)
    )
  }
}

/**
 * Apache HttpClient: `new HttpGet(uri)`, `new HttpPost(uri)`, etc.
 */
class ApacheHttpMethodSink extends DataFlow::Node {
  ApacheHttpMethodSink() {
    exists(ClassInstanceExpr cie |
      cie.getConstructedType()
          .getAnAncestor()
          .hasQualifiedName("org.apache.http.client.methods", "HttpRequestBase") and
      this.asExpr() = cie.getArgument(0)
    )
  }
}

/**
 * Java 11+ HttpRequest.newBuilder().uri(URI.create(tainted)) --
 * the argument to HttpRequest.Builder.uri().
 */
class JavaHttpRequestUriSink extends DataFlow::Node {
  JavaHttpRequestUriSink() {
    exists(MethodCall mc |
      mc.getMethod() instanceof HttpBuilderUri and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/**
 * `URI.create(str)` -- often used as a wrapper before passing to
 * HttpRequest or other clients, so the string arg is the real sink.
 */
class UriCreateSink extends DataFlow::Node {
  UriCreateSink() {
    exists(MethodCall mc, Method m |
      mc.getMethod() = m and
      m.getDeclaringType().hasQualifiedName("java.net", "URI") and
      m.getName() = "create" and
      m.isStatic() and
      this.asExpr() = mc.getArgument(0)
    )
  }
}

/** Taint-tracking configuration for Spring annotation SSRF. */
module SpringSsrfConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof SpringAnnotatedInputParameter
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof RestTemplateCallSink or
    sink instanceof WebClientCreateSink or
    sink instanceof JavaNetUrlSink or
    sink instanceof ApacheHttpMethodSink or
    sink instanceof JavaHttpRequestUriSink or
    sink instanceof UriCreateSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // Primitive / boxed types cannot carry a URL string.
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType
  }
}

module SpringSsrfFlow = TaintTracking::Global<SpringSsrfConfig>;

from SpringSsrfFlow::PathNode source, SpringSsrfFlow::PathNode sink
where SpringSsrfFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SSRF: user input from Spring annotation-injected $@ flows to an HTTP request.",
  source.getNode(), "parameter"
