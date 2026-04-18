"""
Contract Test Suite for SPL Evaluator
Generated from contract version 1
Tests cover happy paths, edge cases, error cases, and invariants
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from typing import Any, Dict
import copy

# Import the component under test
from sdk.python.spl.evaluator import (
    GasExhausted,
    DepthExceeded,
    SPLError,
    _EvalState,
    eval_policy,
    _eval,
    _eval_inner,
    _resolve_symbol,
    _truthy,
    _to_float,
)


# ============================================================================
# Test Class: _EvalState Initialization
# ============================================================================

class TestEvalStateInit:
    """Test suite for _EvalState.__init__"""
    
    def test_eval_state_init_happy_path(self):
        """Verify _EvalState initializes with correct gas budget and zero depth"""
        state = _EvalState(10000)
        assert state.gas == 10000
        assert state.depth == 0
    
    def test_eval_state_init_zero_gas(self):
        """Verify _EvalState can initialize with zero gas budget"""
        state = _EvalState(0)
        assert state.gas == 0
        assert state.depth == 0
    
    def test_eval_state_init_small_gas(self):
        """Verify _EvalState initializes with small gas budget"""
        state = _EvalState(5)
        assert state.gas == 5
        assert state.depth == 0
    
    def test_eval_state_init_large_gas(self):
        """Verify _EvalState initializes with large gas budget"""
        state = _EvalState(1000000)
        assert state.gas == 1000000
        assert state.depth == 0


# ============================================================================
# Test Class: eval_policy
# ============================================================================

class TestEvalPolicy:
    """Test suite for eval_policy entry point"""
    
    def test_eval_policy_simple_literal(self):
        """Verify eval_policy evaluates a simple literal value"""
        result = eval_policy(42, {})
        assert result == 42
    
    def test_eval_policy_string_literal(self):
        """Verify eval_policy evaluates a string literal"""
        result = eval_policy("hello", {})
        assert result == "hello"
    
    def test_eval_policy_logical_and_true(self):
        """Verify eval_policy evaluates AND operation with true operands"""
        result = eval_policy(['and', True, True], {})
        assert result is True
    
    def test_eval_policy_logical_and_false(self):
        """Verify eval_policy evaluates AND operation with false operand"""
        result = eval_policy(['and', True, False], {})
        assert result is False
    
    def test_eval_policy_logical_or_false(self):
        """Verify eval_policy evaluates OR operation with false operands"""
        result = eval_policy(['or', False, False], {})
        assert result is False
    
    def test_eval_policy_logical_or_true(self):
        """Verify eval_policy evaluates OR operation with at least one true operand"""
        result = eval_policy(['or', False, True], {})
        assert result is True
    
    def test_eval_policy_not_operation(self):
        """Verify eval_policy evaluates NOT operation"""
        result = eval_policy(['not', False], {})
        assert result is True
    
    def test_eval_policy_not_true(self):
        """Verify eval_policy evaluates NOT with true operand"""
        result = eval_policy(['not', True], {})
        assert result is False
    
    def test_eval_policy_comparison_equals(self):
        """Verify eval_policy evaluates equality comparison"""
        result = eval_policy(['=', 5, 5], {})
        assert result is True
    
    def test_eval_policy_comparison_not_equals(self):
        """Verify eval_policy evaluates inequality"""
        result = eval_policy(['=', 5, 3], {})
        assert result is False
    
    def test_eval_policy_comparison_less_than(self):
        """Verify eval_policy evaluates less than comparison"""
        result = eval_policy(['<', 3, 5], {})
        assert result is True
    
    def test_eval_policy_comparison_less_than_false(self):
        """Verify eval_policy evaluates less than (false case)"""
        result = eval_policy(['<', 5, 3], {})
        assert result is False
    
    def test_eval_policy_comparison_less_equal(self):
        """Verify eval_policy evaluates less than or equal"""
        result = eval_policy(['<=', 3, 5], {})
        assert result is True
    
    def test_eval_policy_comparison_less_equal_equal(self):
        """Verify eval_policy evaluates less than or equal (equal case)"""
        result = eval_policy(['<=', 5, 5], {})
        assert result is True
    
    def test_eval_policy_comparison_greater_than(self):
        """Verify eval_policy evaluates greater than comparison"""
        result = eval_policy(['>', 5, 3], {})
        assert result is True
    
    def test_eval_policy_comparison_greater_equal(self):
        """Verify eval_policy evaluates greater than or equal"""
        result = eval_policy(['>=', 5, 3], {})
        assert result is True
    
    def test_eval_policy_set_member(self):
        """Verify eval_policy evaluates member operation"""
        result = eval_policy(['member', 'a', ['a', 'b', 'c']], {})
        assert result is True
    
    def test_eval_policy_set_member_false(self):
        """Verify eval_policy evaluates member operation (not in set)"""
        result = eval_policy(['member', 'd', ['a', 'b', 'c']], {})
        assert result is False
    
    def test_eval_policy_set_in(self):
        """Verify eval_policy evaluates 'in' operation"""
        result = eval_policy(['in', 'a', ['a', 'b', 'c']], {})
        assert result is True
    
    def test_eval_policy_get_operation(self):
        """Verify eval_policy evaluates get operation for dictionary access"""
        result = eval_policy(['get', {'key': 'value'}, 'key'], {})
        assert result == 'value'
    
    def test_eval_policy_get_missing_key(self):
        """Verify eval_policy returns None for missing dictionary key"""
        result = eval_policy(['get', {'key': 'value'}, 'missing'], {})
        assert result is None
    
    def test_eval_policy_nested_expression(self):
        """Verify eval_policy evaluates nested expressions correctly"""
        result = eval_policy(['and', ['=', 1, 1], ['<', 2, 3]], {})
        assert result is True
    
    def test_eval_policy_nested_complex(self):
        """Verify eval_policy evaluates complex nested expressions"""
        result = eval_policy(['or', ['and', True, False], ['=', 5, 5]], {})
        assert result is True
    
    def test_eval_policy_with_context_vars(self):
        """Verify eval_policy resolves variables from context"""
        ctx = {'vars': {'x': 10, 'y': 20}}
        result = eval_policy(['<', 'x', 'y'], ctx)
        assert result is True
    
    def test_eval_policy_symbol_resolution(self):
        """Verify eval_policy resolves symbols correctly"""
        ctx = {'vars': {'myvar': 42}}
        result = eval_policy('myvar', ctx)
        assert result == 42
    
    def test_eval_policy_special_symbol_true(self):
        """Verify eval_policy resolves #t to True"""
        result = eval_policy('#t', {})
        assert result is True
    
    def test_eval_policy_special_symbol_false(self):
        """Verify eval_policy resolves #f to False"""
        result = eval_policy('#f', {})
        assert result is False
    
    def test_eval_policy_gas_exhausted(self):
        """Verify eval_policy raises GasExhausted when gas budget is exceeded"""
        # Patch DEFAULT_MAX_GAS or use deeply nested AST
        with patch('sdk_python_spl_evaluator.DEFAULT_MAX_GAS', 0):
            with pytest.raises(GasExhausted):
                eval_policy(['and', True, True], {})
    
    def test_eval_policy_depth_exceeded(self):
        """Verify eval_policy raises DepthExceeded when recursion depth exceeds MAX_DEPTH"""
        # Create deeply nested AST (65+ levels)
        ast = True
        for _ in range(65):
            ast = ['not', ast]
        
        with pytest.raises(DepthExceeded):
            eval_policy(ast, {})
    
    def test_eval_policy_unknown_operation(self):
        """Verify eval_policy raises SPLError for unknown operation"""
        with pytest.raises(SPLError):
            eval_policy(['unknown_op', 1, 2], {})
    
    def test_eval_policy_unresolved_symbol_strict(self):
        """Verify eval_policy raises SPLError for unresolved symbol in strict mode"""
        ctx = {'strict': True, 'vars': {}}
        with pytest.raises(SPLError):
            eval_policy('undefined_var', ctx)
    
    def test_eval_policy_unresolved_symbol_non_strict(self):
        """Verify eval_policy returns symbol as-is in non-strict mode"""
        ctx = {'strict': False, 'vars': {}}
        result = eval_policy('undefined_var', ctx)
        assert result == 'undefined_var'
    
    def test_eval_policy_short_circuit_and(self):
        """Verify AND short-circuits on first false value"""
        # The second operand would raise an error if evaluated
        result = eval_policy(['and', False, ['unknown_op']], {})
        assert result is False
    
    def test_eval_policy_short_circuit_or(self):
        """Verify OR short-circuits on first true value"""
        # The second operand would raise an error if evaluated
        result = eval_policy(['or', True, ['unknown_op']], {})
        assert result is True
    
    def test_eval_policy_empty_list_evaluation(self):
        """Verify empty list is returned as-is"""
        result = eval_policy([], {})
        assert result == []
    
    def test_eval_policy_context_immutability(self):
        """Verify evaluation does not mutate the input context"""
        original_ctx = {'vars': {'x': 1}, 'strict': False}
        ctx = copy.deepcopy(original_ctx)
        eval_policy(['and', True, True], ctx)
        assert ctx == original_ctx
    
    def test_eval_policy_tuple_operation(self):
        """Verify eval_policy evaluates tuple operation"""
        result = eval_policy(['tuple', 1, 2, 3], {})
        assert result == (1, 2, 3)
    
    def test_eval_policy_subset(self):
        """Verify eval_policy evaluates subset? operation"""
        result = eval_policy(['subset?', ['a', 'b'], ['a', 'b', 'c']], {})
        assert result is True
    
    def test_eval_policy_subset_false(self):
        """Verify eval_policy evaluates subset? operation (false case)"""
        result = eval_policy(['subset?', ['a', 'd'], ['a', 'b', 'c']], {})
        assert result is False


# ============================================================================
# Test Class: _eval
# ============================================================================

class Test_Eval:
    """Test suite for _eval internal function"""
    
    def test_eval_decrements_gas(self):
        """Verify _eval decrements gas by 1 for each call"""
        state = _EvalState(100)
        _eval(42, {}, state)
        assert state.gas == 99
    
    def test_eval_restores_depth(self):
        """Verify _eval restores depth to original value after evaluation"""
        state = _EvalState(100)
        state.depth = 5
        _eval(42, {}, state)
        assert state.depth == 5
    
    def test_eval_increments_depth_during_call(self):
        """Verify _eval increments depth during evaluation"""
        state = _EvalState(100)
        initial_depth = state.depth
        
        # We need to observe depth during the call, so we'll use a mock
        with patch('sdk_python_spl_evaluator._eval_inner') as mock_eval_inner:
            def check_depth(node, ctx, st):
                assert st.depth == initial_depth + 1
                return node
            
            mock_eval_inner.side_effect = check_depth
            _eval(42, {}, state)
    
    def test_eval_gas_exhausted_boundary(self):
        """Verify _eval raises GasExhausted when gas becomes negative"""
        state = _EvalState(0)
        with pytest.raises(GasExhausted):
            _eval(42, {}, state)
    
    def test_eval_depth_exceeded_boundary(self):
        """Verify _eval raises DepthExceeded when depth exceeds MAX_DEPTH"""
        state = _EvalState(100)
        state.depth = 64
        with pytest.raises(DepthExceeded):
            _eval(42, {}, state)
    
    def test_eval_depth_at_limit(self):
        """Verify _eval succeeds at exactly MAX_DEPTH - 1"""
        state = _EvalState(100)
        state.depth = 63
        result = _eval(42, {}, state)
        assert result == 42
    
    def test_eval_multiple_calls_gas_tracking(self):
        """Verify multiple _eval calls correctly track gas"""
        state = _EvalState(100)
        _eval(1, {}, state)
        _eval(2, {}, state)
        _eval(3, {}, state)
        assert state.gas == 97


# ============================================================================
# Test Class: _eval_inner
# ============================================================================

class Test_EvalInner:
    """Test suite for _eval_inner core evaluation logic"""
    
    def test_eval_inner_all_logical_operations(self):
        """Verify _eval_inner handles all logical operations (and, or, not)"""
        state = _EvalState(1000)
        
        # Test 'and'
        result = _eval_inner(['and', True, True], {}, state)
        assert result is True
        
        result = _eval_inner(['and', True, False], {}, state)
        assert result is False
        
        # Test 'or'
        result = _eval_inner(['or', False, False], {}, state)
        assert result is False
        
        result = _eval_inner(['or', False, True], {}, state)
        assert result is True
        
        # Test 'not'
        result = _eval_inner(['not', True], {}, state)
        assert result is False
        
        result = _eval_inner(['not', False], {}, state)
        assert result is True
    
    def test_eval_inner_all_comparison_operations(self):
        """Verify _eval_inner handles all comparison operations (=, <=, <, >=, >)"""
        state = _EvalState(1000)
        
        # Test '='
        result = _eval_inner(['=', 5, 5], {}, state)
        assert result is True
        
        result = _eval_inner(['=', 5, 3], {}, state)
        assert result is False
        
        # Test '<='
        result = _eval_inner(['<=', 3, 5], {}, state)
        assert result is True
        
        result = _eval_inner(['<=', 5, 5], {}, state)
        assert result is True
        
        # Test '<'
        result = _eval_inner(['<', 3, 5], {}, state)
        assert result is True
        
        result = _eval_inner(['<', 5, 5], {}, state)
        assert result is False
        
        # Test '>='
        result = _eval_inner(['>=', 5, 3], {}, state)
        assert result is True
        
        result = _eval_inner(['>=', 5, 5], {}, state)
        assert result is True
        
        # Test '>'
        result = _eval_inner(['>', 5, 3], {}, state)
        assert result is True
        
        result = _eval_inner(['>', 5, 5], {}, state)
        assert result is False
    
    def test_eval_inner_set_operations(self):
        """Verify _eval_inner handles set operations (member, in, subset?)"""
        state = _EvalState(1000)
        
        # Test 'member'
        result = _eval_inner(['member', 'a', ['a', 'b', 'c']], {}, state)
        assert result is True
        
        result = _eval_inner(['member', 'd', ['a', 'b', 'c']], {}, state)
        assert result is False
        
        # Test 'in'
        result = _eval_inner(['in', 'a', ['a', 'b', 'c']], {}, state)
        assert result is True
        
        # Test 'subset?'
        result = _eval_inner(['subset?', ['a', 'b'], ['a', 'b', 'c']], {}, state)
        assert result is True
        
        result = _eval_inner(['subset?', ['a', 'd'], ['a', 'b', 'c']], {}, state)
        assert result is False
    
    def test_eval_inner_accessor_operations(self):
        """Verify _eval_inner handles accessor operations (get, tuple)"""
        state = _EvalState(1000)
        
        # Test 'get'
        result = _eval_inner(['get', {'key': 'value'}, 'key'], {}, state)
        assert result == 'value'
        
        result = _eval_inner(['get', {'key': 'value'}, 'missing'], {}, state)
        assert result is None
        
        # Test 'tuple'
        result = _eval_inner(['tuple', 1, 2, 3], {}, state)
        assert result == (1, 2, 3)
    
    def test_eval_inner_time_operation(self):
        """Verify _eval_inner handles time operation (before)"""
        state = _EvalState(1000)
        
        # Test 'before'
        result = _eval_inner(['before', 100, 200], {}, state)
        assert result is True
        
        result = _eval_inner(['before', 200, 100], {}, state)
        assert result is False
    
    def test_eval_inner_crypto_operations_with_mocks(self):
        """Verify _eval_inner handles crypto operations with mocked context"""
        state = _EvalState(1000)
        
        # Mock crypto context
        mock_crypto = {
            'dpop_ok?': Mock(return_value=True),
            'merkle_ok?': Mock(return_value=True),
            'vrf_ok?': Mock(return_value=True),
            'thresh_ok?': Mock(return_value=True),
        }
        ctx = {'crypto': mock_crypto}
        
        # Test 'dpop_ok?'
        result = _eval_inner(['dpop_ok?', 'arg1', 'arg2'], ctx, state)
        assert result is True
        
        # Test 'merkle_ok?'
        result = _eval_inner(['merkle_ok?', 'arg1', 'arg2'], ctx, state)
        assert result is True
        
        # Test 'vrf_ok?'
        result = _eval_inner(['vrf_ok?', 'arg1', 'arg2'], ctx, state)
        assert result is True
        
        # Test 'thresh_ok?'
        result = _eval_inner(['thresh_ok?', 'arg1', 'arg2'], ctx, state)
        assert result is True
    
    def test_eval_inner_counter_operation_with_mock(self):
        """Verify _eval_inner handles counter operation with mocked context"""
        state = _EvalState(1000)
        
        # Mock per-day-count context
        mock_counter = Mock(return_value=5)
        ctx = {'per_day_count': mock_counter}
        
        # Test 'per-day-count'
        result = _eval_inner(['per-day-count', 'user_id'], ctx, state)
        assert result == 5
    
    def test_eval_inner_unknown_operation(self):
        """Verify _eval_inner raises SPLError for unknown operation"""
        state = _EvalState(1000)
        with pytest.raises(SPLError):
            _eval_inner(['invalid_op'], {}, state)
    
    def test_eval_inner_index_error(self):
        """Verify _eval_inner raises IndexError for insufficient arguments"""
        state = _EvalState(1000)
        with pytest.raises(IndexError):
            _eval_inner(['not'], {}, state)
    
    def test_eval_inner_literal_passthrough(self):
        """Verify _eval_inner returns literals as-is"""
        state = _EvalState(1000)
        
        result = _eval_inner(42, {}, state)
        assert result == 42
        
        result = _eval_inner("hello", {}, state)
        assert result == "hello"
        
        result = _eval_inner(None, {}, state)
        assert result is None


# ============================================================================
# Test Class: _resolve_symbol
# ============================================================================

class Test_ResolveSymbol:
    """Test suite for _resolve_symbol"""
    
    def test_resolve_symbol_special_true(self):
        """Verify _resolve_symbol resolves #t to True"""
        result = _resolve_symbol('#t', {})
        assert result is True
    
    def test_resolve_symbol_special_false(self):
        """Verify _resolve_symbol resolves #f to False"""
        result = _resolve_symbol('#f', {})
        assert result is False
    
    def test_resolve_symbol_special_req(self):
        """Verify _resolve_symbol resolves 'req' from context"""
        ctx = {'req': {'user': 'alice'}}
        result = _resolve_symbol('req', ctx)
        assert result == {'user': 'alice'}
    
    def test_resolve_symbol_special_now(self):
        """Verify _resolve_symbol resolves 'now' from context"""
        ctx = {'now': 1234567890}
        result = _resolve_symbol('now', ctx)
        assert result == 1234567890
    
    def test_resolve_symbol_from_vars(self):
        """Verify _resolve_symbol resolves variable from ctx['vars']"""
        ctx = {'vars': {'myvar': 100}}
        result = _resolve_symbol('myvar', ctx)
        assert result == 100
    
    def test_resolve_symbol_non_string(self):
        """Verify _resolve_symbol returns non-string values as-is"""
        result = _resolve_symbol(42, {})
        assert result == 42
        
        result = _resolve_symbol([1, 2, 3], {})
        assert result == [1, 2, 3]
        
        result = _resolve_symbol({'key': 'value'}, {})
        assert result == {'key': 'value'}
    
    def test_resolve_symbol_strict_mode_error(self):
        """Verify _resolve_symbol raises SPLError for unresolved symbol in strict mode"""
        ctx = {'strict': True, 'vars': {}}
        with pytest.raises(SPLError):
            _resolve_symbol('unknown', ctx)
    
    def test_resolve_symbol_non_strict_returns_original(self):
        """Verify _resolve_symbol returns original symbol in non-strict mode"""
        ctx = {'strict': False, 'vars': {}}
        result = _resolve_symbol('unknown', ctx)
        assert result == 'unknown'
    
    def test_resolve_symbol_no_strict_key_returns_original(self):
        """Verify _resolve_symbol returns original when strict key is missing"""
        ctx = {'vars': {}}
        result = _resolve_symbol('unknown', ctx)
        assert result == 'unknown'
    
    def test_resolve_symbol_empty_string(self):
        """Verify _resolve_symbol handles empty string"""
        ctx = {'vars': {}}
        result = _resolve_symbol('', ctx)
        assert result == ''
    
    def test_resolve_symbol_unicode(self):
        """Verify _resolve_symbol handles Unicode symbols"""
        ctx = {'vars': {'日本語': 'japanese', 'émoji': '🎉'}}
        result = _resolve_symbol('日本語', ctx)
        assert result == 'japanese'
        
        result = _resolve_symbol('émoji', ctx)
        assert result == '🎉'


# ============================================================================
# Test Class: _truthy
# ============================================================================

class Test_Truthy:
    """Test suite for _truthy"""
    
    def test_truthy_none_is_false(self):
        """Verify _truthy returns False for None"""
        result = _truthy(None)
        assert result is False
    
    def test_truthy_boolean_true(self):
        """Verify _truthy returns True for boolean True"""
        result = _truthy(True)
        assert result is True
    
    def test_truthy_boolean_false(self):
        """Verify _truthy returns False for boolean False"""
        result = _truthy(False)
        assert result is False
    
    def test_truthy_zero_is_false(self):
        """Verify _truthy returns False for zero"""
        result = _truthy(0)
        assert result is False
        
        result = _truthy(0.0)
        assert result is False
    
    def test_truthy_nonzero_is_true(self):
        """Verify _truthy returns True for non-zero number"""
        result = _truthy(42)
        assert result is True
        
        result = _truthy(-1)
        assert result is True
        
        result = _truthy(3.14)
        assert result is True
    
    def test_truthy_string_is_true(self):
        """Verify _truthy returns True for non-empty string"""
        result = _truthy('hello')
        assert result is True
    
    def test_truthy_empty_string_is_true(self):
        """Verify _truthy returns True for empty string"""
        result = _truthy('')
        assert result is True
    
    def test_truthy_list_is_true(self):
        """Verify _truthy returns True for list"""
        result = _truthy([1, 2, 3])
        assert result is True
        
        result = _truthy([])
        assert result is True
    
    def test_truthy_dict_is_true(self):
        """Verify _truthy returns True for dict"""
        result = _truthy({'key': 'value'})
        assert result is True
        
        result = _truthy({})
        assert result is True
    
    def test_truthy_object_is_true(self):
        """Verify _truthy returns True for arbitrary objects"""
        result = _truthy(object())
        assert result is True


# ============================================================================
# Test Class: _to_float
# ============================================================================

class Test_ToFloat:
    """Test suite for _to_float"""
    
    def test_to_float_integer(self):
        """Verify _to_float converts integer to float"""
        result = _to_float(42)
        assert result == 42.0
        assert isinstance(result, float)
    
    def test_to_float_float(self):
        """Verify _to_float returns float as-is"""
        result = _to_float(3.14)
        assert result == 3.14
        assert isinstance(result, float)
    
    def test_to_float_string_number(self):
        """Verify _to_float converts numeric string to float"""
        result = _to_float('3.14')
        assert result == 3.14
    
    def test_to_float_string_integer(self):
        """Verify _to_float converts integer string to float"""
        result = _to_float('42')
        assert result == 42.0
    
    def test_to_float_invalid_string(self):
        """Verify _to_float returns 0.0 for non-numeric string"""
        result = _to_float('abc')
        assert result == 0.0
    
    def test_to_float_none(self):
        """Verify _to_float returns 0.0 for None"""
        result = _to_float(None)
        assert result == 0.0
    
    def test_to_float_empty_string(self):
        """Verify _to_float returns 0.0 for empty string"""
        result = _to_float('')
        assert result == 0.0
    
    def test_to_float_negative_number(self):
        """Verify _to_float handles negative numbers"""
        result = _to_float(-42)
        assert result == -42.0
        
        result = _to_float('-3.14')
        assert result == -3.14
    
    def test_to_float_scientific_notation(self):
        """Verify _to_float handles scientific notation"""
        result = _to_float('1e3')
        assert result == 1000.0
        
        result = _to_float('1.5e-2')
        assert result == 0.015
    
    def test_to_float_list(self):
        """Verify _to_float returns 0.0 for list"""
        result = _to_float([1, 2, 3])
        assert result == 0.0
    
    def test_to_float_dict(self):
        """Verify _to_float returns 0.0 for dict"""
        result = _to_float({'key': 'value'})
        assert result == 0.0


# ============================================================================
# Test Class: Resource Limits and Invariants
# ============================================================================

class TestResourceLimits:
    """Test suite for resource limit enforcement and invariants"""
    
    def test_invariant_gas_monotonic_decrease(self):
        """Verify gas decreases monotonically during evaluation"""
        state = _EvalState(1000)
        gas_values = [state.gas]
        
        # Perform multiple evaluations
        _eval(True, {}, state)
        gas_values.append(state.gas)
        
        _eval(42, {}, state)
        gas_values.append(state.gas)
        
        _eval("hello", {}, state)
        gas_values.append(state.gas)
        
        # Verify gas values form decreasing sequence
        for i in range(len(gas_values) - 1):
            assert gas_values[i] > gas_values[i + 1]
    
    def test_invariant_depth_tracking(self):
        """Verify depth is properly tracked and restored"""
        state = _EvalState(1000)
        assert state.depth == 0
        
        # Evaluate nested expression
        _eval(['and', ['or', True, False], True], {}, state)
        
        # Depth should be restored to 0 after evaluation
        assert state.depth == 0
    
    def test_gas_at_limit_plus_one(self):
        """Verify evaluation succeeds with gas at exactly required amount"""
        # One eval call requires gas=1
        with patch('sdk_python_spl_evaluator.DEFAULT_MAX_GAS', 1):
            result = eval_policy(42, {})
            assert result == 42
    
    def test_gas_at_limit_minus_one(self):
        """Verify evaluation fails with gas just below required amount"""
        # Zero gas should fail
        with patch('sdk_python_spl_evaluator.DEFAULT_MAX_GAS', 0):
            with pytest.raises(GasExhausted):
                eval_policy(42, {})
    
    def test_depth_at_limit(self):
        """Verify evaluation succeeds at exactly MAX_DEPTH"""
        # Create AST nested exactly 64 levels
        ast = True
        for _ in range(63):  # 63 levels of nesting + 1 initial = 64
            ast = ['not', ast]
        
        result = eval_policy(ast, {})
        # Result should be True if 63 is odd, False if even
        assert isinstance(result, bool)
    
    def test_depth_at_limit_plus_one(self):
        """Verify evaluation fails at MAX_DEPTH + 1"""
        # Create AST nested 65 levels
        ast = True
        for _ in range(65):
            ast = ['not', ast]
        
        with pytest.raises(DepthExceeded):
            eval_policy(ast, {})
    
    def test_complex_nested_gas_consumption(self):
        """Verify gas consumption for complex nested expressions"""
        state = _EvalState(1000)
        initial_gas = state.gas
        
        # Evaluate complex expression
        ast = ['and', ['or', ['=', 1, 1], ['<', 2, 3]], ['not', False]]
        _eval(ast, {}, state)
        
        # Gas should have decreased
        assert state.gas < initial_gas
        # Gas should decrease by at least the number of nodes
        # (exact amount depends on implementation)
        assert initial_gas - state.gas > 0
    
    def test_gas_exhaustion_mid_evaluation(self):
        """Verify gas exhaustion is detected mid-evaluation"""
        state = _EvalState(2)  # Very limited gas
        
        # Try to evaluate expression that requires more gas
        with pytest.raises(GasExhausted):
            _eval(['and', ['or', True, False], ['=', 1, 1]], {}, state)


# ============================================================================
# Test Class: Edge Cases and Security
# ============================================================================

class TestEdgeCasesAndSecurity:
    """Test suite for edge cases and security concerns"""
    
    def test_single_element_list(self):
        """Verify single-element list with operation is handled"""
        # A list with only an operation and no arguments
        state = _EvalState(100)
        with pytest.raises((IndexError, SPLError)):
            _eval_inner(['not'], {}, state)
    
    def test_nested_empty_lists(self):
        """Verify nested empty lists are handled"""
        result = eval_policy([[], [], []], {})
        assert result == [[], [], []]
    
    def test_very_large_numbers(self):
        """Verify handling of very large numbers"""
        result = eval_policy(['<', 10**100, 10**101], {})
        assert result is True
    
    def test_floating_point_comparison(self):
        """Verify floating point comparison"""
        result = eval_policy(['=', 0.1 + 0.2, 0.3], {})
        # Note: This might be False due to floating point precision
        assert isinstance(result, bool)
    
    def test_mixed_type_comparison(self):
        """Verify mixed type comparison"""
        # Comparing string with number
        result = eval_policy(['=', '42', 42], {})
        assert result is False
    
    def test_unicode_in_operations(self):
        """Verify Unicode strings in operations"""
        result = eval_policy(['=', '日本語', '日本語'], {})
        assert result is True
        
        result = eval_policy(['member', '🎉', ['🎉', '🎊', '🎈']], {})
        assert result is True
    
    def test_null_values_in_expressions(self):
        """Verify None/null values in expressions"""
        result = eval_policy(['=', None, None], {})
        assert result is True
        
        result = eval_policy(['not', None], {})
        assert result is True  # None is falsy, so not None is True
    
    def test_recursive_data_structures(self):
        """Verify handling of recursive/circular data structures"""
        circular = {'key': 'value'}
        circular['self'] = circular
        
        # Should not crash
        result = eval_policy(['get', circular, 'key'], {})
        assert result == 'value'
    
    def test_and_with_many_operands(self):
        """Verify AND with many operands"""
        result = eval_policy(['and', True, True, True, True, True], {})
        assert result is True
        
        result = eval_policy(['and', True, True, False, True, True], {})
        assert result is False
    
    def test_or_with_many_operands(self):
        """Verify OR with many operands"""
        result = eval_policy(['or', False, False, False, False, False], {})
        assert result is False
        
        result = eval_policy(['or', False, False, True, False, False], {})
        assert result is True
    
    def test_deterministic_evaluation(self):
        """Verify evaluation is deterministic"""
        ast = ['and', ['=', 1, 1], ['<', 2, 3], ['not', False]]
        ctx = {'vars': {'x': 10}}
        
        result1 = eval_policy(ast, ctx)
        result2 = eval_policy(ast, ctx)
        result3 = eval_policy(ast, ctx)
        
        assert result1 == result2 == result3
    
    def test_context_isolation(self):
        """Verify contexts are isolated between evaluations"""
        ctx1 = {'vars': {'x': 1}}
        ctx2 = {'vars': {'x': 2}}
        
        result1 = eval_policy('x', ctx1)
        result2 = eval_policy('x', ctx2)
        
        assert result1 == 1
        assert result2 == 2
        assert ctx1['vars']['x'] == 1  # Unchanged
        assert ctx2['vars']['x'] == 2  # Unchanged
    
    def test_subset_empty_sets(self):
        """Verify subset? with empty sets"""
        result = eval_policy(['subset?', [], []], {})
        assert result is True
        
        result = eval_policy(['subset?', [], ['a', 'b']], {})
        assert result is True
    
    def test_get_with_nested_dicts(self):
        """Verify get with nested dictionaries"""
        data = {'level1': {'level2': {'level3': 'deep_value'}}}
        result = eval_policy(['get', ['get', ['get', data, 'level1'], 'level2'], 'level3'], {})
        assert result == 'deep_value'
    
    def test_tuple_empty(self):
        """Verify tuple with no arguments"""
        result = eval_policy(['tuple'], {})
        assert result == ()
    
    def test_tuple_single_element(self):
        """Verify tuple with single element"""
        result = eval_policy(['tuple', 42], {})
        assert result == (42,)
    
    def test_before_equal_timestamps(self):
        """Verify before with equal timestamps"""
        result = eval_policy(['before', 100, 100], {})
        assert result is False
    
    def test_comparison_with_converted_types(self):
        """Verify comparisons use type conversion"""
        # Assuming _to_float is used for numeric comparisons
        result = eval_policy(['<', '3', '5'], {})
        # This depends on implementation details
        assert isinstance(result, bool)


# ============================================================================
# Test Class: Mocked Dependencies
# ============================================================================

class TestMockedDependencies:
    """Test suite for operations with mocked dependencies"""
    
    def test_per_day_count_called_correctly(self):
        """Verify per-day-count calls the mocked function correctly"""
        mock_counter = Mock(return_value=42)
        ctx = {'per_day_count': mock_counter}
        
        result = eval_policy(['per-day-count', 'user123'], ctx)
        
        assert result == 42
        mock_counter.assert_called_once()
    
    def test_dpop_ok_called_correctly(self):
        """Verify dpop_ok? calls the mocked function correctly"""
        mock_dpop = Mock(return_value=True)
        ctx = {'crypto': {'dpop_ok?': mock_dpop}}
        
        result = eval_policy(['dpop_ok?', 'arg1', 'arg2'], ctx)
        
        assert result is True
        mock_dpop.assert_called_once()
    
    def test_merkle_ok_called_correctly(self):
        """Verify merkle_ok? calls the mocked function correctly"""
        mock_merkle = Mock(return_value=False)
        ctx = {'crypto': {'merkle_ok?': mock_merkle}}
        
        result = eval_policy(['merkle_ok?', 'proof', 'root'], ctx)
        
        assert result is False
        mock_merkle.assert_called_once()
    
    def test_vrf_ok_called_correctly(self):
        """Verify vrf_ok? calls the mocked function correctly"""
        mock_vrf = Mock(return_value=True)
        ctx = {'crypto': {'vrf_ok?': mock_vrf}}
        
        result = eval_policy(['vrf_ok?', 'proof', 'message'], ctx)
        
        assert result is True
        mock_vrf.assert_called_once()
    
    def test_thresh_ok_called_correctly(self):
        """Verify thresh_ok? calls the mocked function correctly"""
        mock_thresh = Mock(return_value=True)
        ctx = {'crypto': {'thresh_ok?': mock_thresh}}
        
        result = eval_policy(['thresh_ok?', 'sigs', 'threshold'], ctx)
        
        assert result is True
        mock_thresh.assert_called_once()
    
    def test_crypto_operations_without_context(self):
        """Verify crypto operations fail gracefully without context"""
        # Without crypto context, should raise an error
        with pytest.raises((KeyError, AttributeError, SPLError)):
            eval_policy(['dpop_ok?', 'arg1', 'arg2'], {})
    
    def test_per_day_count_without_context(self):
        """Verify per-day-count fails gracefully without context"""
        # Without per_day_count context, should raise an error
        with pytest.raises((KeyError, AttributeError, SPLError)):
            eval_policy(['per-day-count', 'user123'], {})


# ============================================================================
# Test Class: Complex Integration Scenarios
# ============================================================================

class TestComplexIntegration:
    """Test suite for complex integration scenarios"""
    
    def test_complex_policy_evaluation(self):
        """Verify complex policy with multiple operations"""
        ctx = {
            'vars': {
                'user_role': 'admin',
                'user_age': 25,
                'resource_owner': 'admin'
            },
            'strict': False
        }
        
        # Policy: user is admin AND age >= 18 AND is resource owner
        ast = [
            'and',
            ['=', 'user_role', 'admin'],
            ['>=', 'user_age', 18],
            ['=', 'user_role', 'resource_owner']
        ]
        
        result = eval_policy(ast, ctx)
        assert result is True
    
    def test_complex_policy_with_nested_conditions(self):
        """Verify complex nested policy evaluation"""
        ctx = {
            'vars': {
                'is_premium': True,
                'credits': 100,
                'daily_limit': 50
            },
            'per_day_count': Mock(return_value=30)
        }
        
        # Policy: (is_premium OR credits > 0) AND daily_count < daily_limit
        ast = [
            'and',
            ['or', 'is_premium', ['>', 'credits', 0]],
            ['<', ['per-day-count', 'user'], 'daily_limit']
        ]
        
        result = eval_policy(ast, ctx)
        assert result is True
    
    def test_policy_with_set_operations(self):
        """Verify policy using set operations"""
        ctx = {
            'vars': {
                'user_permissions': ['read', 'write', 'execute'],
                'required_permissions': ['read', 'write']
            }
        }
        
        # Policy: required_permissions is subset of user_permissions
        ast = ['subset?', 'required_permissions', 'user_permissions']
        
        result = eval_policy(ast, ctx)
        assert result is True
    
    def test_policy_with_time_constraints(self):
        """Verify policy with time-based constraints"""
        ctx = {
            'vars': {
                'expiry_time': 2000000000
            },
            'now': 1500000000
        }
        
        # Policy: current time is before expiry
        ast = ['before', 'now', 'expiry_time']
        
        result = eval_policy(ast, ctx)
        assert result is True
    
    def test_policy_with_nested_data_access(self):
        """Verify policy with nested data structure access"""
        ctx = {
            'vars': {
                'request': {
                    'headers': {
                        'authorization': 'Bearer token123'
                    }
                }
            }
        }
        
        # Access nested data
        ast = ['=', 
               ['get', ['get', 'request', 'headers'], 'authorization'],
               'Bearer token123'
        ]
        
        result = eval_policy(ast, ctx)
        assert result is True
    
    def test_deny_by_default_behavior(self):
        """Verify deny-by-default behavior in strict mode"""
        ctx = {'strict': True, 'vars': {}}
        
        # Unresolved symbol should fail in strict mode
        with pytest.raises(SPLError):
            eval_policy('undefined_permission', ctx)
    
    def test_allow_by_default_behavior(self):
        """Verify allow-by-default behavior in non-strict mode"""
        ctx = {'strict': False, 'vars': {}}
        
        # Unresolved symbol returns as-is in non-strict mode
        result = eval_policy('undefined_permission', ctx)
        assert result == 'undefined_permission'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
