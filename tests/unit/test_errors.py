# ==============================================================================
# File:         tests/unit/test_errors.py
# Synopsis:     Unit tests for exception hierarchy, cleanup stack, retry
# Version:      1.2.1
# ==============================================================================

import pytest
from apotropaios.core.constants import ErrorCode
from apotropaios.core.errors import (
    ApotropaiosError, BackupError, CleanupStack, ErrorContext,
    FirewallNotFoundError, LockTimeoutError, RuleNotFoundError,
    ValidationError, retry, with_fallback,
)


class TestExceptionHierarchy:
    def test_base_carries_code(self) -> None:
        exc = ApotropaiosError("test", ErrorCode.GENERAL)
        assert exc.code == ErrorCode.GENERAL
        assert exc.message == "test"

    def test_subclass_codes(self) -> None:
        assert RuleNotFoundError("x").code == ErrorCode.RULE_NOT_FOUND
        assert FirewallNotFoundError("x").code == ErrorCode.FW_NOT_FOUND
        assert ValidationError("x").code == ErrorCode.VALIDATION_FAIL
        assert BackupError("x").code == ErrorCode.BACKUP_FAIL

    def test_lock_timeout_inherits(self) -> None:
        exc = LockTimeoutError("timeout")
        assert exc.code == ErrorCode.LOCK_TIMEOUT
        assert isinstance(exc, ApotropaiosError)

    def test_context_dict(self) -> None:
        exc = RuleNotFoundError("missing", rule_id="abc-123")
        assert exc.context["rule_id"] == "abc-123"


class TestCleanupStack:
    def test_lifo_order(self) -> None:
        order: list[int] = []
        cs = CleanupStack()
        cs.register(lambda: order.append(1), "first")
        cs.register(lambda: order.append(2), "second")
        cs.register(lambda: order.append(3), "third")
        cs.execute_all()
        assert order == [3, 2, 1]

    def test_recursion_guard(self) -> None:
        cs = CleanupStack()
        cs.register(lambda: cs.execute_all(), "recursive")
        cs.register(lambda: None, "normal")
        cs.execute_all()  # Should not infinite loop

    def test_unregister(self) -> None:
        items: list[str] = []
        fn_a = lambda: items.append("a")
        fn_b = lambda: items.append("b")
        cs = CleanupStack()
        cs.register(fn_a)
        cs.register(fn_b)
        cs.unregister(fn_a)
        cs.execute_all()
        assert items == ["b"]

    def test_failure_continues(self) -> None:
        order: list[int] = []
        cs = CleanupStack()
        cs.register(lambda: order.append(1))
        cs.register(lambda: (_ for _ in ()).throw(RuntimeError("fail")))
        cs.register(lambda: order.append(3))
        cs.execute_all()
        assert 3 in order and 1 in order


class TestErrorContext:
    def test_record_and_format(self) -> None:
        ctx = ErrorContext()
        assert ctx.get_formatted() == ""
        try:
            raise ValueError("test error")
        except ValueError as exc:
            ctx.record(exc, function="my_func", line=42)
        fmt = ctx.get_formatted()
        assert "my_func" in fmt
        assert "42" in fmt
        assert "ValueError" in fmt

    def test_clear(self) -> None:
        ctx = ErrorContext()
        ctx.record(ValueError("x"), function="f")
        ctx.clear()
        assert ctx.get_formatted() == ""


class TestRetry:
    def test_succeeds_on_retry(self) -> None:
        count = 0
        def flaky() -> str:
            nonlocal count
            count += 1
            if count < 3:
                raise ValueError("not yet")
            return "ok"
        result = retry(flaky, max_retries=5, initial_delay=0.01)
        assert result == "ok"
        assert count == 3

    def test_exhaustion_raises(self) -> None:
        def always_fails() -> None:
            raise RuntimeError("permanent")
        with pytest.raises(RuntimeError, match="permanent"):
            retry(always_fails, max_retries=2, initial_delay=0.01)


class TestWithFallback:
    def test_primary_succeeds(self) -> None:
        result = with_fallback(lambda: "primary", lambda: "fallback")
        assert result == "primary"

    def test_fallback_used(self) -> None:
        def fail() -> str:
            raise ValueError("fail")
        result = with_fallback(fail, lambda: "fallback")
        assert result == "fallback"

    def test_both_fail(self) -> None:
        def fail1() -> str:
            raise ValueError("primary")
        def fail2() -> str:
            raise RuntimeError("fallback")
        with pytest.raises(RuntimeError, match="fallback"):
            with_fallback(fail1, fail2)
