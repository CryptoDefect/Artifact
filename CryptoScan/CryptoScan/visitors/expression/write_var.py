from typing import Any, List, Optional

from CryptoScan.core.expressions import NewElementaryType
from CryptoScan.visitors.expression.expression import ExpressionVisitor
from CryptoScan.core.expressions.assignment_operation import AssignmentOperation
from CryptoScan.core.expressions.binary_operation import BinaryOperation
from CryptoScan.core.expressions.call_expression import CallExpression
from CryptoScan.core.expressions.conditional_expression import ConditionalExpression
from CryptoScan.core.expressions.elementary_type_name_expression import ElementaryTypeNameExpression
from CryptoScan.core.expressions.expression import Expression
from CryptoScan.core.expressions.identifier import Identifier
from CryptoScan.core.expressions.index_access import IndexAccess
from CryptoScan.core.expressions.literal import Literal
from CryptoScan.core.expressions.member_access import MemberAccess
from CryptoScan.core.expressions.new_array import NewArray
from CryptoScan.core.expressions.new_contract import NewContract
from CryptoScan.core.expressions.tuple_expression import TupleExpression
from CryptoScan.core.expressions.type_conversion import TypeConversion
from CryptoScan.core.expressions.unary_operation import UnaryOperation


key = "WriteVar"


def get(expression: Expression) -> List[Any]:
    val = expression.context[key]
    # we delete the item to reduce memory use
    del expression.context[key]
    return val


def set_val(expression: Expression, val: List[Any]) -> None:
    expression.context[key] = val


class WriteVar(ExpressionVisitor):
    def __init__(self, expression: Expression) -> None:
        self._result: Optional[List[Expression]] = None
        super().__init__(expression)

    def result(self) -> List[Any]:
        if self._result is None:
            self._result = list(set(get(self.expression)))
        return self._result

    def _post_binary_operation(self, expression: BinaryOperation) -> None:
        left = get(expression.expression_left)
        right = get(expression.expression_right)
        val = left + right
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_call_expression(self, expression: CallExpression) -> None:
        called = get(expression.called)
        args = [get(a) for a in expression.arguments if a]
        args = [item for sublist in args for item in sublist]
        val = called + args
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_conditional_expression(self, expression: ConditionalExpression) -> None:
        if_expr = get(expression.if_expression)
        else_expr = get(expression.else_expression)
        then_expr = get(expression.then_expression)
        val = if_expr + else_expr + then_expr
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_assignement_operation(self, expression: AssignmentOperation) -> None:
        left = get(expression.expression_left)
        right = get(expression.expression_right)
        val = left + right
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_elementary_type_name_expression(
        self, expression: ElementaryTypeNameExpression
    ) -> None:
        set_val(expression, [])

    # save only identifier expression
    def _post_identifier(self, expression: Identifier) -> None:
        if expression.is_lvalue:
            set_val(expression, [expression])
        else:
            set_val(expression, [])

    #        if isinstance(expression.value, Variable):
    #            set_val(expression, [expression.value])
    #        else:
    #            set_val(expression, [])

    def _post_index_access(self, expression: IndexAccess) -> None:
        left = get(expression.expression_left)
        right = get(expression.expression_right)
        val = left + right
        if expression.is_lvalue:
            #       val += [expression]
            val += [expression.expression_left]
        #       n = expression.expression_left
        # parse all the a.b[..].c[..]
        #      while isinstance(n, (IndexAccess, MemberAccess)):
        #          if isinstance(n, IndexAccess):
        #              val += [n.expression_left]
        #              n = n.expression_left
        #          else:
        #              val += [n.expression]
        #              n = n.expression
        set_val(expression, val)

    def _post_literal(self, expression: Literal) -> None:
        set_val(expression, [])

    def _post_member_access(self, expression: MemberAccess) -> None:
        expr = get(expression.expression)
        val = expr
        if expression.is_lvalue:
            val += [expression]
            val += [expression.expression]
        set_val(expression, val)

    def _post_new_array(self, expression: NewArray) -> None:
        set_val(expression, [])

    def _post_new_contract(self, expression: NewContract) -> None:
        set_val(expression, [])

    def _post_new_elementary_type(self, expression: NewElementaryType) -> None:
        set_val(expression, [])

    def _post_tuple_expression(self, expression: TupleExpression) -> None:
        expressions = [get(e) for e in expression.expressions if e]
        val = [item for sublist in expressions for item in sublist]
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_type_conversion(self, expression: TypeConversion) -> None:
        expr = get(expression.expression)
        val = expr
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)

    def _post_unary_operation(self, expression: UnaryOperation) -> None:
        expr = get(expression.expression)
        val = expr
        if expression.is_lvalue:
            val += [expression]
        set_val(expression, val)
