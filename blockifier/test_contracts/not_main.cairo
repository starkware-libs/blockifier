func not_main(num: felt) {
    [ap] = num;
    assert [ap] = 1;
    ret;
}

func main() {
    ret;
}
