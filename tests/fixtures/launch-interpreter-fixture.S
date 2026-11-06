/* A PIE that names an interpreter hidden by the memory assignment. */
.global _start
.text
_start:
    mov $88, %edi
    mov $60, %eax
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
