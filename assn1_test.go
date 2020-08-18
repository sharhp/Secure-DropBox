package assn1

import (
	"reflect"
	"testing"

	"github.com/sarkarbidya/CS628-assn1/userlib"
)

// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInitUser(t *testing.T) {
	t.Log("Initialization test")
	userlib.DebugPrint = true
	userlib.DebugPrint = false
	_, err1 := InitUser("", "")
	if err1 != nil {
		t.Log("Failed to initialize user")

	} else {
		t.Error("Initialized invalid user", err1)
	}

	// add more test cases here
}

func TestUserStorage(t *testing.T) {
	u1, err1 := GetUser("", "fubar")
	if err1 != nil {
		t.Log("Cannot load data for invalid user", u1)
	} else {
		t.Error("Data loaded for invalid user", err1)
	}

	// add more test cases here
}

func TestFileStoreLoadAppend(t *testing.T) {
	data1 := userlib.RandomBytes(5 * configBlockSize)
	u1, err1 := InitUser("usernmae", "password")
	if err1 != nil {
		t.Error("Cannot load data for invalid user", u1)
	}

	//Store Load File TestCase
	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil {
		t.Error("Cannot store file file1", ab1)
	}
	data2, ab := u1.LoadFile("file1", 0)
	if ab != nil {
		t.Error("Cannot Load file file1", ab)
	}
	if !reflect.DeepEqual(data1[:configBlockSize], data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}

	//Append File TestCase

	datanew1 := userlib.RandomBytes(5 * configBlockSize)

	ab = u1.AppendFile("file1", datanew1)
	if ab != nil {
		t.Error("Cannot append to file file1", ab)
	}

	data2, ab = u1.LoadFile("file1", 5)
	if ab != nil {
		t.Error("Cannot Load file file1", ab)
	}
	if !reflect.DeepEqual(datanew1[:configBlockSize], data2) {

		t.Error("data corrupted")
	} else {
		t.Log("data is not corrupted")
	}
	// add test cases here
}

func TestFileShareReceive(t *testing.T) {
	// add test cases here

	data1 := userlib.RandomBytes(4096)
	u1, err1 := InitUser("usernmae", "password")
	u1, err1 = GetUser("usernmae", "password")
	u2, err1 := InitUser("usernmae1", "password1")
	u2, err1 = GetUser("usernmae1", "password1")
	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil || err1 != nil {
		t.Error("Cannot store file file1", ab1)
	}
	msg, err := u1.ShareFile("file1", "usernmae1")
	err = u2.ReceiveFile("abc", "usernmae", msg)
	data2, ab := u2.LoadFile("abc", 0)
	if ab != nil || err != nil {
		t.Error("Cannot Load file file1\n", ab)
	}
	if !reflect.DeepEqual(data1, data2) {

		t.Error("File share failed")
	} else {
		t.Log("File shared sucessfully")
	}

}

func TestFileMutlipleUserAppend(t *testing.T) {
	data1 := userlib.RandomBytes(4096)
	u1, err1 := InitUser("usernmae", "password")
	u1, err1 = GetUser("usernmae", "password")
	u2, err1 := InitUser("usernmae1", "password1")
	u2, err1 = GetUser("usernmae1", "password1")

	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil || err1 != nil {
		t.Error("Cannot store file file1", ab1)
	}

	msg, err := u1.ShareFile("file1", "usernmae1")
	err = u2.ReceiveFile("abc", "usernmae", msg)
	if err != nil {
		t.Error("ShareFile/ReceiveFile Failed", ab1)
	}
	datanew1 := userlib.RandomBytes(4096)
	ab := u2.AppendFile("abc", datanew1)
	if ab != nil {
		t.Error("Cannot append to file abc", ab)
	}

	data2, ab := u1.LoadFile("file1", 1)
	if ab != nil || !reflect.DeepEqual(datanew1, data2) {
		t.Error("Cannot Load file file1\n", ab)
	} else {
		t.Log("Passed")
	}
}

func TestFileShareReceiveMutate(t *testing.T) {
	data1 := userlib.RandomBytes(configBlockSize)
	u1, err1 := InitUser("usernmae", "password")
	u1, err1 = GetUser("usernmae", "password")
	u2, err1 := InitUser("usernmae1", "password1")
	u2, err1 = GetUser("usernmae1", "password1")

	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil || err1 != nil {
		t.Error("Cannot store file file1", ab1)
	}

	msg, err := u1.ShareFile("file1", "usernmae1")
	msg += "blahblah"
	err = u2.ReceiveFile("abc", "usernmae", msg)
	if err == nil {
		t.Error("ShareFile/ReceiveFile Mutate Failed", ab1)
	} else {
		t.Log("Passed")
	}

	data2, ab := u1.LoadFile("abc", 0)
	if ab == nil || reflect.DeepEqual(data1, data2) {
		t.Error("Receive Failed\n", ab)
	} else {
		t.Log("Passed")
	}
}

func TestFileShareRevokeCollaborator(t *testing.T) {
	// add test cases here

	data1 := userlib.RandomBytes(4096)
	u1, err1 := InitUser("usernmae", "password")
	u1, err1 = GetUser("usernmae", "password")
	u2, err1 := InitUser("usernmae1", "password1")
	u2, err1 = GetUser("usernmae1", "password1")

	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil || err1 != nil {
		t.Error("Cannot store file file1", ab1)
	}

	msg, err := u1.ShareFile("file1", "usernmae1")
	err = u2.ReceiveFile("abc", "usernmae", msg)

	data2, ab := u2.LoadFile("abc", 0)
	if ab != nil || err != nil {
		t.Error("Cannot Load file file1\n", ab)
	}
	if !reflect.DeepEqual(data1, data2) {
		t.Error("File share failed")
	} else {
		t.Log("File shared sucessfully")
	}

	err = u2.RevokeFile("abc")
	if err == nil {
		t.Error("Revoke Failed", ab)
	} else {
		t.Log("Working")
	}

	data2, ab = u2.LoadFile("abc", 0)
	if ab == nil && reflect.DeepEqual(data1, data2) {
		t.Log("Working", ab)
	} else {
		t.Error("Failed")
	}
}

func TestFileLoadMutate(t *testing.T) {
	// add test cases here

	data1 := userlib.RandomBytes(4096)
	u1, err1 := InitUser("usernmae", "password")
	u1, err1 = GetUser("usernmae", "password")

	ab1 := u1.StoreFile("file1", data1)
	if ab1 != nil || err1 != nil {
		t.Error("Cannot store file file1", ab1)
	}

	userlib.DatastoreClear()

	data2, ab := u1.LoadFile("file1", 0)
	if ab == nil || reflect.DeepEqual(data1, data2) {
		t.Error("Failed")
	} else {
		t.Log("Working", ab)
	}
}

func TestSingleInitGetUser(t *testing.T) {
	// add test cases here

	u1, err := InitUser("usernmae", "password")
	u2, err1 := GetUser("usernmae", "password")

	if err != nil || err1 != nil {
		t.Error("Failed", err)
	} else {
		t.Log("Working")
	}

	if reflect.DeepEqual(u1, u2) {
		t.Log("Working")
	} else {
		t.Error("Failed")
	}
}

func TestDataStoreClear(t *testing.T) {
	u1, err := InitUser("usernmae", "password")
	u2, err1 := GetUser("usernmae", "password")

	if err != nil || err1 != nil || u1 == nil || u2 == nil {
		t.Error("Failed", err)
	} else {
		t.Log("Working")
	}

	a := userlib.DatastoreGetMap()
	for k, v := range a {
		userlib.DatastoreSet(k, userlib.RandomBytes(4096))
		t.Log(v)
	}
	u2, err1 = GetUser("usernmae", "password")
	if err1 == nil {
		t.Error("Failed", err)
	} else {
		t.Log("Working")
	}
	t.Log(a)
	userlib.DatastoreClear()
	a = userlib.DatastoreGetMap()
	t.Log(a)
}

func TestFileShareReceiveNew(t *testing.T) {

	// set up
	data := userlib.RandomBytes(configBlockSize * 20)
	u1, err := InitUser("un1", "pw1")
	u2, err := InitUser("un2", "pw2")
	u3, err := InitUser("un3", "pw3")
	ab := u1.StoreFile("file1", data)
	if ab != nil || err != nil {
		t.Error("Cannot store file file1", ab)
	}
	msg1, err := u1.ShareFile("file1", "un2")
	err = u2.ReceiveFile("file2", "un1", msg1)

	msg2, err := u2.ShareFile("file2", "un3")
	err = u3.ReceiveFile("file3", "un2", msg2)

	// u1, u2 and u3 read after share & receive
	data2, ab := u2.LoadFile("file2", 10)
	if ab != nil || err != nil {
		t.Error("Cannot Load file file2\n", ab)
	}
	data1, ab := u1.LoadFile("file1", 10)
	if ab != nil || err != nil {
		t.Error("Cannot Load file file1\n", ab)
	}
	data3, ab := u3.LoadFile("file3", 10)
	if ab != nil {
		t.Error("Cannot Load file file3\n", ab)
	}
	// benign case - both read same data
	if !reflect.DeepEqual(data1, data2) || !reflect.DeepEqual(data3, data2) {
		t.Error("data corrupted")
	} else {
		t.Log("data is valid")
	}

	// u1 revokes

	err = u1.RevokeFile("file1")
	if err != nil {
		t.Error("Revoke Failed\n", ab)
	}
	//u1 updates
	dataappend1 := userlib.RandomBytes(configBlockSize)
	err = u1.AppendFile("file1", dataappend1)
	if err == nil {
		t.Log("Append Sucessfull")
	} else {
		t.Error("Append unsucessfull")
	}

	// u2 attempts to read after revoke
	data2, ab = u2.LoadFile("file2", 21)
	if data2 != nil {
		t.Error("Reading some data after revoke")
	} else {
		t.Log("Illegal Read failed after revoke")
	}

	// u3 attempts to read after revoke
	data3, ab = u3.LoadFile("file3", 21)
	if data3 != nil {
		t.Error("Reading some data after revoke")
	} else {
		t.Log("Illegal Read failed after revoke")
	}

	// u1 read after revoke
	data1ar, ab := u1.LoadFile("file1", 10)
	if ab != nil || err != nil {
		t.Error("Cannot Load file file1\n", ab)
	}
	if !reflect.DeepEqual(data1ar, data1) {
		t.Error("data not intact")
	} else {
		t.Log("data intact")
	}

	// u2 tries to update after revoke
	data2 = userlib.RandomBytes(configBlockSize)
	err = u2.AppendFile("file2", data2)
	if err == nil {
		t.Error("Appending some data after revoke")
	} else {
		t.Log("Illegal Append failed after revoke")
	}

	// u1 shouldn't read any update (original file isn't modified)
	data1, err = u1.LoadFile("file1", 21)
	if err == nil {
		t.Error("File tampered after revoke")
	} else {
		t.Log("File not tampered after revoke")
	}

	//u2 tries to receive again	and attempts to read
	err = u2.ReceiveFile("file2", "un1", msg1)
	if err == nil {
		t.Log("Receive after Revoke Failed")
	}
	data2, ab = u2.LoadFile("file2", 21)
	if data2 != nil {
		t.Error("Reading some data after revoke")
	} else {
		t.Log("Illegal Read failed after revoke")
	}

	err = u3.ReceiveFile("file3", "un1", msg1)
	if err != nil {
		t.Log("did not Receive after Revoke Failed")
	} else {
		t.Error("Recieved without sharing")
	}
}
