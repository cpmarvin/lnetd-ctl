extern "C" {
    #include "foo.h" //a C header, so wrap it in extern "C" 
}

int main() {
  foo();
  return(0);
}
