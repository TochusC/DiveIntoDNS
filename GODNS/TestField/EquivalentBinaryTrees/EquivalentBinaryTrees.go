package main

import "golang.org/x/tour/tree"
import "fmt"

// Walk walks the tree t sending all values
// from the tree to the channel ch.
func Walk(t *tree.Tree, ch chan int){
  if(t == nil){
  	close(ch)
	return
  }
  leftCh := make(chan int)
  go Walk(t.Left, leftCh)
  
  for val := range leftCh{
    ch<-val
  }

  ch<-t.Value

  rightCh := make(chan int)
  go Walk(t.Right, rightCh)

  for val := range rightCh{
    ch<-val
  }
  close(ch)
}

// Same determines whether the trees
// t1 and t2 contain the same values.
func Same(t1, t2 *tree.Tree) bool{
  t1ch := make(chan int, 10)
  t2ch := make(chan int, 10)
  
  go Walk(t1, t1ch)
  go Walk(t2, t2ch)
  
  for leftVal := range t1ch{
    rightVal, ok := <- t2ch
    
	fmt.Printf("leftVal: %d, rightVal: %d\n", leftVal, rightVal)
	
    if ok == false || leftVal != rightVal{
      return false
    }
	
  }

  _, ok := <-t2ch
  if ok == false{
    return true
  }
  return false
}

func main() {
	fmt.Println(Same(tree.New(10), tree.New(10)))
}
