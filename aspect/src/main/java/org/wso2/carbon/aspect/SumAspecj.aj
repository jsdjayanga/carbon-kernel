package org.wso2.carbon.aspect;

/**
 * Created by jayanga on 10/5/16.
 */
public aspect SumAspecj {
        before() : execution(* *.sum(..)) {
        System.out.println("Before execution sum test1");
        }
}
