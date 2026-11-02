/**
 * @name Use of iterator after container mutation
 * @description A container mutation may invalidate an iterator that is used
 *              afterward without replacement. Invalidation depends on the
 *              container and operation; node insertion preserves iterators.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id raptor/cpp/iterator-invalidation
 * @tags security
 *       correctness
 *       external/cwe/cwe-416
 *       external/cwe/cwe-825
 */

import IteratorInvalidationFlow

from ContainerMutation mutation, IteratorUse use
where invalidIteratorUse(mutation, use)
select use,
  "Iterator '" + use.getTarget().getName() + "' is used after $@ on container '" +
    mutation.getContainer().getName() + "', which may invalidate it.", mutation,
  mutation.getTarget().getName() + "()"
