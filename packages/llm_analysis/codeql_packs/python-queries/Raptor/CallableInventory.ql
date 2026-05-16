/**
 * @id raptor/iris/python/callable-inventory
 * @name IRIS Tier 1 Layer 3 callable inventory probe
 * @description Lists every source-extracted Function in the DB. Used
 *              by IRIS Tier 1 to decide whether a 0-match result is
 *              genuine refutation or whether the DB extractor
 *              silently dropped the callable. Probe runs once per
 *              (DB, language); result is cached and consulted
 *              whenever a refute decision is about to fire.
 * @kind problem
 * @severity recommendation
 * @tags raptor-internal
 * @precision high
 */

import python

from Function f
where exists(f.getLocation())
select f, "RAPTOR_CALLABLE:" + f.getName()
