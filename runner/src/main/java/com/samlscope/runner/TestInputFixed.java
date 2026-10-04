package com.samlscope.runner;

/** A Run's supplemental test inputs are already fixed; replacement requires a new Run. */
public final class TestInputFixed extends IllegalStateException {
    public TestInputFixed(String message) { super(message); }
}
