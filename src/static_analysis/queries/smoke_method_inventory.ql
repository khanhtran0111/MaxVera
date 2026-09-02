/**
 * @name MaxVera smoke method inventory
 * @description Confirms that a Java CodeQL database can execute a local query.
 * @kind problem
 * @problem.severity recommendation
 * @precision very-high
 * @id java/maxvera/smoke-method-inventory
 * @tags maintainability
 */

import java

from Method method
where method.getName() = "main"
select method, "Phase 3 smoke query reached an extracted Java method."
