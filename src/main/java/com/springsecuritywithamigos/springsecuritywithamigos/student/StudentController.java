package com.springsecuritywithamigos.springsecuritywithamigos.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
    private static final List<Student> students = Arrays.asList(
            new Student(1,"King"),
            new Student(2,"Wanyama")
    );
    @GetMapping(path = "{studentId}")
    Student getStudent(@PathVariable("studentId") Integer studentId){
        return students.stream().filter(student ->
            studentId.equals(student.getStudentId())).findFirst().orElseThrow(()->
                new IllegalStateException("Student with id "+studentId+" not found"));
    }
    @GetMapping
    List<Student> getStudents(){
        return students;
    }
}
