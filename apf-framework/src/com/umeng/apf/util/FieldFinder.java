package com.umeng.apf.util;

import java.lang.reflect.Field;

public class FieldFinder<T> {
    private Object object;
    private String fieldName;
    private boolean isInited = false;
    private Field field;

    public FieldFinder(Object obj, String name) {
        if (obj == null) {
            throw new IllegalArgumentException("object cannot be null.");
        }
        object = obj;
        fieldName = name;
    }

    private void init() throws NoSuchFieldException {
        if (isInited) {
            return;
        }
        Class<?> clazz = object.getClass();
        while (clazz != null)
            try {
                field = clazz.getDeclaredField(fieldName);
                field.setAccessible(true);
                return;
            } catch (NoSuchFieldException e) {
                if (clazz.getSuperclass() != null)
                    clazz = clazz.getSuperclass();
                else
                    throw e;
            }
    }

    @SuppressWarnings("unchecked")
    public T get() throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        init();

        if (field == null) {
            throw new NoSuchFieldException();
        }

        try {
            return (T) field.get(object);
        } catch (ClassCastException e) {
        }
        throw new IllegalArgumentException("unable to cast object");
    }

    public void set(T val) throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        init();

        if (field == null) {
            throw new NoSuchFieldException();
        }
        field.set(object, val);
    }
}