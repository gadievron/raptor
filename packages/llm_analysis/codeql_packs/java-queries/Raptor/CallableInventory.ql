/**
 * @id raptor/iris/java/callable-inventory
 * @name IRIS Tier 1 Layer 3 callable inventory probe
 * @description Lists every source-extracted Callable in the DB. Used
 *              by IRIS Tier 1 Layer 3 coverage gate to decide whether
 *              a 0-match dataflow result is genuine refutation or
 *              whether the Java extractor silently dropped the
 *              callable (common when a single class fails to compile
 *              but its source still ends up in src.zip).
 * @kind problem
 * @severity recommendation
 * @tags raptor-internal
 * @precision high
 */

import java

from Callable c
where c.fromSource()
select c, "RAPTOR_CALLABLE:" + c.getName()
