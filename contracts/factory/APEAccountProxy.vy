# @version 0.3.9
"""
@title Ape Wallet APEAccountProxy
@author zkApes
@license Copyright (c) zkApes, 2022-2023 - all rights reserved
"""

interface APELibraryManager:
	def modules_library(_module_id: uint256) -> address: view

event Received:
	_sender: indexed(address)
	_amount: indexed(uint256)
	_data: Bytes[1024]

library: public(address)
initialized: public(bool)


@view
@external
def implementation() -> address:
	return APELibraryManager(self.library).modules_library(4)


@external
def initialize(_library: address) -> bool:
	assert not self.initialized, "APE100"

	self.library = _library
	self.initialized = True
	return True


@payable
@external
def __default__() -> Bytes[255]:

	target: address = APELibraryManager(self.library).modules_library(4)

	if len(msg.data) == 0:
		log Received(msg.sender, msg.value, b"")
		return b""

	response: Bytes[255] = raw_call(
		target,
		msg.data,
		max_outsize=255,
		value=msg.value,
		is_delegate_call=True
	)

	assert len(response) != 0, "APE001"
	return response



