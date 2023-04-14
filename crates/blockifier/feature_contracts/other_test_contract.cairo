%lang starknet

@external
func assert_0_is_1() {
    assert 0 = 1;
    return ();
}
