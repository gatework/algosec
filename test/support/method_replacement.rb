# frozen_string_literal: true

module MethodReplacement
  def replace_method(object, name, implementation)
    original = object.method(name)
    object.define_singleton_method(name) { |*args, **options, &block| implementation.call(*args, **options, &block) }
    yield
  ensure
    object.define_singleton_method(name, original) if original
  end
end
